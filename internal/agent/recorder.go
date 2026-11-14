package agent

import (
	"encoding/base64"
	"log"
	"sync"
	"time"

	"aegis-one/rc/internal/rec"
	"aegis-one/rc/internal/wire"
)

const (
	recFlushEvery = 5 * time.Second
	recFlushBytes = 512 << 10
	recKeyEvery   = 30 * time.Second // a full keyframe so playback can recover from a lost chunk
)

// recorder encrypts the session's screen stream on the device and uploads it in chunks. The
// plaintext never leaves the agent: the server stores sealed chunks it can only open at
// playback time with the recording private key.
type recorder struct {
	mu        sync.Mutex
	session   string
	seal      *rec.Sealer
	send      func(wire.Msg)
	buf       []byte
	n         uint64
	start     time.Time
	lastFlush time.Time
	lastKey   time.Time
	frames    int
	closed    bool
}

func newRecorder(c wire.OpenRC, w, h int, send func(wire.Msg)) (*recorder, error) {
	pub, err := base64.StdEncoding.DecodeString(c.RecPub)
	if err != nil {
		return nil, err
	}
	seal, hdr, err := rec.NewSealer(pub, c.RecKeyID, c.Session)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	r := &recorder{session: c.Session, seal: seal, send: send, start: now, lastFlush: now}
	send(wire.Msg{T: "rec_open", Session: c.Session, Rec: &wire.RecHeader{KeyID: hdr.KeyID, EphPub: hdr.EphPub, Wrapped: hdr.Wrapped},
		Screen: &wire.ScreenSz{W: w, H: h}})
	log.Printf("recording %s: encrypted on this device for server recording key %s", c.Session, c.RecKeyID)
	return r, nil
}

// wantKey reports whether the next frame should be a full keyframe.
func (r *recorder) wantKey(now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return !r.closed && (r.lastKey.IsZero() || now.Sub(r.lastKey) >= recKeyEvery)
}

// add appends screen messages (internal/screen format) with their time offset.
func (r *recorder) add(msgs [][]byte, key bool, now time.Time) {
	if len(msgs) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	t := uint32(now.Sub(r.start) / time.Millisecond)
	for _, m := range msgs {
		r.buf = rec.AppendFrame(r.buf, t, m)
	}
	r.frames++
	if key {
		r.lastKey = now
	}
	if len(r.buf) >= recFlushBytes || now.Sub(r.lastFlush) >= recFlushEvery {
		r.flushLocked(now)
	}
}

func (r *recorder) flushLocked(now time.Time) {
	r.lastFlush = now
	if len(r.buf) == 0 {
		return
	}
	sealed := r.seal.Seal(r.n, r.buf)
	r.send(wire.Msg{T: "rec_chunk", Session: r.session, N: int64(r.n), Data: base64.StdEncoding.EncodeToString(sealed)})
	r.n++
	r.buf = nil
}

func (r *recorder) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	now := time.Now()
	r.flushLocked(now)
	r.closed = true
	dur := now.Sub(r.start).Milliseconds()
	r.send(wire.Msg{T: "rec_close", Session: r.session, N: dur})
	log.Printf("recording %s: %d chunks, %d frames, %ds", r.session, r.n, r.frames, dur/1000)
}
