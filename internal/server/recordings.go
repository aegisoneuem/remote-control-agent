package server

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"aegis-one/rc/internal/rec"
	"aegis-one/rc/internal/store"
	"aegis-one/rc/internal/wire"
)

// Session ids are minted by start() as "RC-" + 6 hex digits; anything else is refused before it
// can become part of a file path.
var sessionID = regexp.MustCompile(`^RC-[0-9A-F]{6}$`)

const (
	maxChunkBytes = 2 << 20 // one sealed chunk
	maxChunks     = 200000  // about 11 days at one chunk every 5 s
)

func (s *Server) recDir(session string) string {
	return filepath.Join(s.cfg.DataDir, "recordings", session)
}

// onRecording stores what the agent uploads. The server never sees plaintext here: chunks arrive
// sealed with a data key that only the recording private key can unwrap.
func (s *Server) onRecording(ac *agentConn, m wire.Msg) {
	if !sessionID.MatchString(m.Session) {
		return
	}
	s.mu.Lock()
	is, ok := s.issued[m.Session]
	s.mu.Unlock()
	if !ok || is.device != ac.info.Device {
		slog.Warn("recording upload for a session this server did not issue to the device", "session", m.Session, "device", ac.info.Device)
		return
	}
	switch m.T {
	case "rec_open":
		if m.Rec == nil || m.Rec.KeyID != s.recKeyID {
			slog.Warn("recording header refused", "session", m.Session)
			return
		}
		if err := os.MkdirAll(s.recDir(m.Session), 0o700); err != nil {
			slog.Error("recording folder", "err", err)
			return
		}
		s.mu.Lock()
		days := s.policy.RetentionDays
		s.mu.Unlock()
		w, h := 0, 0
		if m.Screen != nil {
			w, h = m.Screen.W, m.Screen.H
		}
		now := time.Now()
		err := s.db.StartRecording(store.Recording{Session: m.Session, Device: is.device, Operator: is.operator, Reason: is.reason, Started: now,
			Width: w, Height: h, KeyID: m.Rec.KeyID, EphPub: m.Rec.EphPub, WrappedKey: m.Rec.Wrapped, Expires: now.AddDate(0, 0, days)})
		if err != nil {
			slog.Error("recording start", "err", err)
			return
		}
		s.audit(wire.AuditEntry{Event: "recording_started", Operator: is.operator, Device: is.device, Session: m.Session,
			Detail: fmt.Sprintf("encrypted for recording key %s · kept %d days", m.Rec.KeyID, days)})
	case "rec_chunk":
		if m.N < 0 || m.N >= maxChunks {
			return
		}
		b, err := base64.StdEncoding.DecodeString(m.Data)
		if err != nil || len(b) == 0 || len(b) > maxChunkBytes {
			return
		}
		r, found, err := s.db.Recording(m.Session)
		if err != nil || !found || r.Status != "recording" {
			return
		}
		if err := os.WriteFile(filepath.Join(s.recDir(m.Session), strconv.FormatInt(m.N, 10)+".bin"), b, 0o600); err != nil {
			slog.Error("recording chunk write", "err", err)
			return
		}
		_ = s.db.AddChunk(m.Session, m.N, int64(len(b)))
	case "rec_close":
		r, found, err := s.db.Recording(m.Session)
		if err != nil || !found || r.Status != "recording" {
			return
		}
		_ = s.db.FinishRecording(m.Session, time.Now(), m.N)
		s.audit(wire.AuditEntry{Event: "recording_saved", Operator: r.Operator, Device: r.Device, Session: m.Session,
			Detail: fmt.Sprintf("%d s · %d chunks · encrypted", m.N/1000, r.Chunks)})
	}
}

func (s *Server) recList() []wire.RecInfo {
	rs, err := s.db.Recordings(200)
	if err != nil {
		slog.Error("recording list", "err", err)
		return nil
	}
	out := make([]wire.RecInfo, 0, len(rs))
	for _, r := range rs {
		i := wire.RecInfo{Session: r.Session, Device: r.Device, Operator: r.Operator, Reason: r.Reason, Started: r.Started.UTC().Format(time.RFC3339),
			DurationMS: r.DurationMS, Bytes: r.Bytes, Chunks: r.Chunks, Status: r.Status, Expires: r.Expires.UTC().Format(time.RFC3339), W: r.Width, H: r.Height}
		if !r.Ended.IsZero() {
			i.Ended = r.Ended.UTC().Format(time.RFC3339)
		}
		out = append(out, i)
	}
	return out
}

// playRecording decrypts a recording chunk by chunk and streams the plaintext frames to an
// operator with remotecontrol.recording.view. Every playback is audited.
func (s *Server) playRecording(cc *consoleConn, session string) {
	fail := func(text string) { _ = cc.c.send(wire.Msg{T: "rec_end", Session: session, Text: text}) }
	if !sessionID.MatchString(session) {
		fail("Unknown recording.")
		return
	}
	r, found, err := s.db.Recording(session)
	if err != nil || !found {
		fail("Unknown recording.")
		return
	}
	op, err := rec.NewOpener(s.recKey, rec.Header{KeyID: r.KeyID, EphPub: r.EphPub, Wrapped: r.WrappedKey}, session)
	if err != nil {
		fail("The recording key could not be unwrapped: " + err.Error())
		return
	}
	s.audit(wire.AuditEntry{Event: "recording_viewed", Operator: cc.op.Name, Device: r.Device, Session: session})
	_ = cc.c.send(wire.Msg{T: "rec_meta", Session: session, Recs: []wire.RecInfo{s.recInfo(r)}})
	for n := int64(0); n < r.Chunks; n++ {
		sealed, err := os.ReadFile(filepath.Join(s.recDir(session), strconv.FormatInt(n, 10)+".bin"))
		if err != nil {
			continue // a lost chunk leaves a gap; the next keyframe recovers the picture
		}
		plain, err := op.Open(uint64(n), sealed)
		if err != nil {
			s.audit(wire.AuditEntry{Event: "recording_tampered", Device: r.Device, Session: session, Detail: err.Error()})
			fail("Chunk " + strconv.FormatInt(n, 10) + " failed its integrity check. Playback stopped.")
			return
		}
		if err := cc.c.send(wire.Msg{T: "rec_data", Session: session, N: n, Data: base64.StdEncoding.EncodeToString(plain)}); err != nil {
			return
		}
	}
	_ = cc.c.send(wire.Msg{T: "rec_end", Session: session})
}

func (s *Server) recInfo(r store.Recording) wire.RecInfo {
	return wire.RecInfo{Session: r.Session, Device: r.Device, Operator: r.Operator, Reason: r.Reason, Started: r.Started.UTC().Format(time.RFC3339),
		DurationMS: r.DurationMS, Bytes: r.Bytes, Chunks: r.Chunks, Status: r.Status, W: r.Width, H: r.Height}
}

// sweepRecordings deletes recordings past their retention date.
func (s *Server) sweepRecordings(now time.Time) {
	ids, err := s.db.ExpiredRecordings(now)
	if err != nil {
		slog.Error("retention sweep", "err", err)
		return
	}
	for _, id := range ids {
		if !sessionID.MatchString(id) {
			continue
		}
		if err := os.RemoveAll(s.recDir(id)); err != nil {
			slog.Error("retention delete", "session", id, "err", err)
			continue
		}
		_ = s.db.DeleteRecording(id)
		s.audit(wire.AuditEntry{Event: "recording_deleted", Session: id, Detail: "retention period ended"})
	}
}
