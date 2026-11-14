// Package agent is the endpoint side of Aegis Remote Control.
//
// Flow, following the agent-track RC design:
//  1. The agent keeps an outbound TLS 1.3 connection to the server (signaling only).
//  2. The server sends a signed open_rc. The agent verifies the Ed25519 signature against its
//     trusted key set, the TTL and replay, and that the command is for this device.
//  3. Consent first: the signed-in user is told who is asking, what kind of session, why,
//     whether it is recorded and for how long, plus a verification code. Nothing starts until
//     they accept. Escalations (full control, command line, restart) ask again.
//  4. The agent dials back with a WebRTC offer; screen, input, control, chat and shell run on
//     data channels peer to peer. The agent, not the console, enforces who may send input.
//  5. Policy from the signed command is enforced here: idle and maximum duration, privacy mode,
//     and cleanup when the session ends (release keys, clear clipboard, optional lock).
package agent

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pion/ice/v4"
	"github.com/pion/rtcp"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"

	"aegis-one/rc/internal/platform"
	"aegis-one/rc/internal/screen"
	"aegis-one/rc/internal/video"
	"aegis-one/rc/internal/wire"
)

type Config struct {
	Server      string // wss://host:8443
	EnrollToken string
	Device      string
	TrustedKeys map[string]ed25519.PublicKey
	CertSHA256  string // pinned server certificate (hex SHA-256 of DER)
	Insecure    bool   // accept any certificate (first-run testing only)
	AllowReboot bool
	ICEServers  []string
	Version     string
	FPS         int
	ServiceMode bool   // running as the SYSTEM helper of the Windows service
	Video       bool   // offer an H.264 video track (needs FFmpeg); JPEG tiles stay as fallback
	FFmpeg      string // FFmpeg path; empty = next to the agent or on PATH
	VideoFPS    int    // frame rate while video is in use (default 25)
	VideoKbps   int    // target bitrate (default 2500)
}

type Agent struct {
	inputFails atomic.Int64
	inputOK    atomic.Int64
	ffmpeg     string
	cfg        Config
	plat       platform.Platform
	api        *webrtc.API

	wmu sync.Mutex
	ws  *websocket.Conn

	mu   sync.Mutex
	used map[string]time.Time
	sess *session
}

type session struct {
	id, reason string
	policy     wire.Policy
	started    time.Time
	ctl        string // psid of the controller
	peers      map[string]*peer
	lastInput  time.Time
	privacy    bool
	approved   map[string]bool // per-action approvals given by the end user
	asking     atomic.Bool     // a consent prompt is open
	stop       chan struct{}
	enc        *screen.Encoder
	fps        int
	capErr     string
	rec        *recorder // encrypted recording, when policy requires one
	venc       *video.Encoder
	vkey       atomic.Bool // restart the encoder for a fresh keyframe (new viewer, PLI)
	vlastKey   time.Time
	vfailed    bool
}

type peer struct {
	psid, operator, operatorID, role, mode string
	pc                                     *webrtc.PeerConnection
	ch                                     map[string]*webrtc.DataChannel
	needKey                                atomic.Bool
	screenOpen                             atomic.Bool
	recovering                             atomic.Bool // an ICE restart is in progress
	video                                  *webrtc.TrackLocalStaticSample
	videoOn                                atomic.Bool // the browser plays the video track
	dropped                                int
}

func New(cfg Config, p platform.Platform) *Agent {
	se := webrtc.SettingEngine{}
	se.SetICEMulticastDNSMode(ice.MulticastDNSModeQueryOnly) // resolve browsers' .local candidates
	if cfg.FPS <= 0 {
		cfg.FPS = 12
	}
	if cfg.VideoFPS <= 0 {
		cfg.VideoFPS = 25
	}
	if cfg.VideoKbps <= 0 {
		cfg.VideoKbps = 2500
	}
	a := &Agent{cfg: cfg, plat: p, api: webrtc.NewAPI(webrtc.WithSettingEngine(se)), used: map[string]time.Time{}}
	if cfg.Video {
		if ff, err := video.FindFFmpeg(cfg.FFmpeg); err == nil {
			a.ffmpeg = ff
			log.Printf("video: H.264 through %s (JPEG tiles remain the fallback)", ff)
		} else {
			log.Printf("video: FFmpeg not found (%v); using JPEG tiles", err)
		}
	}
	p.OnChat(a.onUserChat)
	return a
}

// onUserChat forwards what the end user types in the chat window to everyone in the session.
func (a *Agent) onUserChat(text string) {
	if len(text) > 500 {
		text = text[:500]
	}
	a.mu.Lock()
	s := a.sess
	a.mu.Unlock()
	if s == nil {
		a.plat.ChatShow("Aegis One", "No session is active, so the message was not sent.")
		return
	}
	who := a.plat.ActiveUser()
	a.forEach(func(p *peer) { sendJSON(p.ch["chat"], map[string]any{"who": who, "x": text}) })
	a.event(s.id, "chat_from_user", who, "the end user sent a chat message")
}

/* ---------------- server connection ---------------- */

func (a *Agent) Run() {
	backoff := time.Second
	for {
		err := a.connectOnce()
		log.Printf("server connection closed: %v (retrying in %s)", err, backoff)
		time.Sleep(backoff)
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (a *Agent) tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13, // TLS 1.3 only
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // replaced by the certificate pin below
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("server sent no certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			got := hex.EncodeToString(sum[:])
			if a.cfg.CertSHA256 == "" {
				if a.cfg.Insecure {
					log.Printf("WARNING: server certificate not pinned (sha256 %s)", got)
					return nil
				}
				return fmt.Errorf("server certificate is not pinned; got sha256 %s", got)
			}
			if !strings.EqualFold(strings.ReplaceAll(a.cfg.CertSHA256, ":", ""), got) {
				return fmt.Errorf("server certificate does not match the pin (got %s)", got)
			}
			return nil
		},
	}
}

func (a *Agent) connectOnce() error {
	d := websocket.Dialer{TLSClientConfig: a.tlsConfig(), HandshakeTimeout: 10 * time.Second, Proxy: http.ProxyFromEnvironment}
	c, resp, err := d.Dial(strings.TrimRight(a.cfg.Server, "/")+"/ws/agent", nil)
	if err != nil {
		if resp != nil {
			return fmt.Errorf("dial: %w (HTTP %d)", err, resp.StatusCode)
		}
		return fmt.Errorf("dial: %w", err)
	}
	defer c.Close()
	if st, ok := c.UnderlyingConn().(*tls.Conn); ok {
		log.Printf("connected to %s over %s", a.cfg.Server, tlsName(st.ConnectionState().Version))
	}
	a.wmu.Lock()
	a.ws = c
	a.wmu.Unlock()
	w, h := a.plat.ScreenSize()
	a.send(wire.Msg{T: "agent_auth", Token: a.cfg.EnrollToken, Device: a.cfg.Device, OS: a.plat.OS(), User: a.plat.ActiveUser(),
		IP: localIP(), Version: a.cfg.Version, Caps: a.caps(), Screen: &wire.ScreenSz{W: w, H: h}})
	a.sendState()
	for {
		var m wire.Msg
		if err := c.ReadJSON(&m); err != nil {
			return err
		}
		switch m.T {
		case "auth_ok":
			log.Printf("enrolled with the server as %s", a.cfg.Device)
		case "open_rc":
			go a.handleOpen(m)
		case "rc_answer":
			a.onAnswer(m)
		case "rc_ice":
			a.onICE(m)
		case "rc_close":
			a.onClose(m)
		case "error":
			log.Printf("server: %s", m.Text)
		}
	}
}

func tlsName(v uint16) string {
	if v == tls.VersionTLS13 {
		return "TLS 1.3"
	}
	return fmt.Sprintf("TLS 0x%04x", v)
}

func (a *Agent) shellRights() string {
	if a.cfg.ServiceMode {
		return "Commands run as the local SYSTEM account (full administrator rights)."
	}
	return "Commands run with your user rights."
}

func (a *Agent) caps() []string {
	c := []string{"remote_control", "privacy_mode", "shell", "chat"}
	if a.cfg.AllowReboot {
		c = append(c, "reboot")
	}
	if a.cfg.ServiceMode {
		c = append(c, "system_service", "secure_desktop", "sas", "recording")
	} else {
		c = append(c, "recording")
	}
	return c
}

func (a *Agent) send(m wire.Msg) {
	a.wmu.Lock()
	defer a.wmu.Unlock()
	if a.ws == nil {
		return
	}
	_ = a.ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := a.ws.WriteJSON(m); err != nil {
		log.Printf("send %s: %v", m.T, err)
	}
}

func (a *Agent) event(session, k, operator, text string) {
	log.Printf("event %s: %s", k, text)
	a.send(wire.Msg{T: "rc_event", Session: session, K: k, Text: text, Extra: map[string]any{"operator": operator}})
}

func (a *Agent) sendState() {
	a.mu.Lock()
	var si *wire.SessionInfo
	if s := a.sess; s != nil {
		c := s.peers[s.ctl]
		si = &wire.SessionInfo{ID: s.id, People: len(s.peers), Started: s.started.UnixMilli(), Reason: s.reason}
		if c != nil {
			si.Operator, si.Mode = c.operator, c.mode
		}
	}
	a.mu.Unlock()
	a.send(wire.Msg{T: "agent_state", User: a.plat.ActiveUser(), Session2: si})
}

/* ---------------- open_rc: verify, consent, attach ---------------- */

func (a *Agent) deny(psid, code, reason string) {
	log.Printf("refused %s (%s): %s", psid, code, reason)
	a.send(wire.Msg{T: "rc_deny", PSID: psid, Close: code, Reason: reason})
}

func (a *Agent) handleOpen(m wire.Msg) {
	c, err := wire.Verify(a.cfg.TrustedKeys, m.CmdB64, m.Sig, m.KeyID, time.Now())
	if err != nil {
		if errors.Is(err, wire.ErrBadSignature) {
			a.deny(m.PSID, wire.CloseInvalidCommand, "Signature check failed. The request was not signed by a trusted server key.")
		} else {
			a.deny(m.PSID, wire.CloseInvalidCommand, "Request rejected: "+err.Error())
		}
		return
	}
	if c.SID != m.PSID {
		a.deny(m.PSID, wire.CloseInvalidCommand, "Session id does not match the signed request.")
		return
	}
	if !strings.EqualFold(c.Device, a.cfg.Device) {
		a.deny(c.SID, wire.CloseInvalidCommand, "This request is for a different device.")
		return
	}
	a.mu.Lock()
	for k, t := range a.used { // forget ids long past their TTL
		if time.Since(t) > 10*time.Minute {
			delete(a.used, k)
		}
	}
	if _, seen := a.used[c.SID]; seen {
		a.mu.Unlock()
		a.deny(c.SID, wire.CloseInvalidCommand, "Session id was already used (replay rejected).")
		return
	}
	a.used[c.SID] = time.Now()
	s := a.sess
	var busy string
	switch {
	case c.Role == "viewer" && (s == nil || s.id != c.Session):
		busy = "That session is no longer active."
	case c.Role != "viewer" && s != nil && s.id == c.Session && s.peers[s.ctl] != nil && s.peers[s.ctl].operatorID != c.OperatorID:
		// only the current controller may reopen its own session (for example chat-only to screen)
		busy = "Only the current controller can reopen this session."
	case c.Role != "viewer" && s != nil && s.id != c.Session:
		op := ""
		if p := s.peers[s.ctl]; p != nil {
			op = p.operator
		}
		busy = fmt.Sprintf("%s is already in a session controlled by %s. Join it as a viewer instead.", a.cfg.Device, op)
	case s != nil && s.asking.Load():
		busy = "The user is answering another request. Try again in a moment."
	}
	a.mu.Unlock()
	if busy != "" {
		a.deny(c.SID, wire.CloseDeviceBusy, busy)
		return
	}
	a.send(wire.Msg{T: "rc_status", PSID: c.SID, K: "verified", KeyID: m.KeyID})
	log.Printf("open_rc verified (Ed25519 key %s, TTL %ds) from %s: %s %s", m.KeyID, c.TTL, c.Operator, c.Role, c.Mode)

	// Consent first.
	user := a.plat.ActiveUser()
	if user == "" {
		if c.Policy.Consent != "unattended_if_no_user" {
			a.deny(c.SID, wire.CloseNoUser, "Nobody is signed in to approve the session, and policy requires consent.")
			return
		}
		a.event(c.Session, "consent_skipped", c.Operator, "No signed-in user; policy allows unattended access")
	} else {
		code := wire.VerifyCode(c.SID)
		a.send(wire.Msg{T: "rc_status", PSID: c.SID, K: "consent_wait", Code: code, User: user})
		title := "Remote support request"
		if c.Role == "viewer" {
			title = "Another technician wants to watch"
		}
		ok := a.plat.Consent(platform.ConsentRequest{Title: title, Operator: c.Operator, Action: map[bool]string{true: "join", false: "session"}[c.Role == "viewer"],
			Lines: consentLines(c, code), Timeout: 60 * time.Second})
		if !ok {
			a.event(c.Session, "consent_declined", c.Operator, user+" declined or did not answer")
			a.deny(c.SID, wire.CloseUserDeclined, user+" declined the session or did not answer within 60 seconds.")
			return
		}
		a.event(c.Session, "consent_granted", c.Operator, user+" accepted: "+wire.ModeText(c.Mode))
	}
	if err := a.attach(c); err != nil {
		a.deny(c.SID, wire.ClosePeerFailed, "Could not start the connection: "+err.Error())
	}
}

func consentLines(c wire.OpenRC, code string) []string {
	who := c.Operator + " from IT support wants to start a remote session on this computer."
	if c.Role == "viewer" {
		who = c.Operator + " from IT support wants to watch the current session (view only)."
	}
	rec := "No"
	if c.Policy.Record {
		rec = "Yes, the screen is recorded for audit"
	}
	l := []string{who, "", "Session type: " + wire.ModeText(c.Mode)}
	if c.Reason != "" {
		l = append(l, "Reason: "+c.Reason)
	}
	l = append(l, "Recorded: "+rec,
		fmt.Sprintf("Time limit: ends after %d min, or after %d min without activity", c.Policy.MaxSec/60, c.Policy.IdleSec/60))
	if c.Policy.PerActionConsent {
		l = append(l, "Full control, the command line and a restart each need your approval again.")
	}
	l = append(l, "", "Verification code: "+code+"  (the technician sees the same code)",
		"You can end the session at any time with End session on the banner at the top of the screen.")
	return l
}

func (a *Agent) attach(c wire.OpenRC) error {
	var ice []webrtc.ICEServer
	for _, u := range a.cfg.ICEServers {
		ice = append(ice, webrtc.ICEServer{URLs: []string{u}})
	}
	for _, s := range c.ICE { // signed by the server: STUN plus short-lived TURN credentials
		e := webrtc.ICEServer{URLs: s.URLs}
		if s.Username != "" {
			e.Username, e.Credential, e.CredentialType = s.Username, s.Credential, webrtc.ICECredentialTypePassword
		}
		ice = append(ice, e)
	}
	pc, err := a.api.NewPeerConnection(webrtc.Configuration{ICEServers: ice})
	if err != nil {
		return err
	}
	p := &peer{psid: c.SID, operator: c.Operator, operatorID: c.OperatorID, role: c.Role, mode: c.Mode, pc: pc, ch: map[string]*webrtc.DataChannel{}}
	if c.Role == "viewer" {
		p.mode = "view"
	}
	ordered, unordered, zero := true, false, uint16(0)
	for _, l := range []string{"screen", "input", "control", "chat", "shell"} {
		dc, err := pc.CreateDataChannel(l, &webrtc.DataChannelInit{Ordered: &ordered})
		if err != nil {
			pc.Close()
			return err
		}
		p.ch[l] = dc
		label := l
		dc.OnMessage(func(msg webrtc.DataChannelMessage) { a.onPeerMsg(p, label, msg.Data) })
		switch l {
		case "screen":
			dc.OnOpen(func() {
				log.Printf("screen channel open for %s", p.operator)
				p.needKey.Store(true)
				p.screenOpen.Store(true)
			})
		case "control":
			dc.OnOpen(func() { a.roster() })
		}
	}
	if a.ffmpeg != "" && c.Mode != "chat" {
		tr, err := webrtc.NewTrackLocalStaticSample(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeH264, ClockRate: 90000,
			SDPFmtpLine: "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f"}, "screen", "aegis-screen")
		if err == nil {
			if snd, err := pc.AddTrack(tr); err == nil {
				p.video = tr
				p.videoOn.Store(true)
				go func() { // a viewer that lost a frame asks for a keyframe (PLI/FIR)
					for {
						pkts, _, err := snd.ReadRTCP()
						if err != nil {
							return
						}
						for _, pk := range pkts {
							switch pk.(type) {
							case *rtcp.PictureLossIndication, *rtcp.FullIntraRequest:
								if s := a.curSession(); s != nil {
									s.vkey.Store(true)
								}
							}
						}
					}
				}()
			}
		}
	}
	mv, err := pc.CreateDataChannel("move", &webrtc.DataChannelInit{Ordered: &unordered, MaxRetransmits: &zero})
	if err == nil {
		p.ch["move"] = mv
		mv.OnMessage(func(msg webrtc.DataChannelMessage) { a.onPeerMsg(p, "move", msg.Data) })
	}
	pc.OnICECandidate(func(cand *webrtc.ICECandidate) {
		if cand == nil {
			return
		}
		b, _ := json.Marshal(cand.ToJSON())
		a.send(wire.Msg{T: "rc_ice", PSID: p.psid, C: b})
	})
	pc.OnConnectionStateChange(func(st webrtc.PeerConnectionState) {
		log.Printf("peer %s (%s): %s", p.psid, p.operator, st)
		switch st {
		case webrtc.PeerConnectionStateDisconnected, webrtc.PeerConnectionStateFailed:
			go a.recoverPeer(p)
		case webrtc.PeerConnectionStateClosed:
			a.drop(p.psid, wire.ClosePeerFailed, p.operator+" disconnected")
		}
	})

	a.mu.Lock()
	s := a.sess
	if s == nil {
		s = &session{id: c.Session, reason: c.Reason, policy: c.Policy, started: time.Now(), peers: map[string]*peer{},
			lastInput: time.Now(), approved: map[string]bool{}, stop: make(chan struct{}), enc: screen.NewEncoder(), fps: a.cfg.FPS}
		a.sess = s
		if c.Policy.Record && c.RecPub != "" && c.Role != "viewer" {
			w, h := a.plat.ScreenSize()
			if r, err := newRecorder(c, w, h, a.send); err != nil {
				log.Printf("recording could not start: %v", err)
			} else {
				s.rec = r
			}
		}
		go a.stream(s)
		go a.limits(s)
	}
	// the same operator reopening (for example chat-only upgraded to screen) replaces their old peer
	for id, old := range s.peers {
		if old.operatorID == c.OperatorID && old.role == c.Role {
			delete(s.peers, id)
			go old.pc.Close()
		}
	}
	s.peers[p.psid] = p
	if c.Role != "viewer" {
		s.ctl = p.psid
		s.approved = map[string]bool{"control": c.Mode == "control"} // the session consent covered the mode asked for
	}
	a.mu.Unlock()

	offer, err := pc.CreateOffer(nil)
	if err != nil {
		return err
	}
	if err := pc.SetLocalDescription(offer); err != nil {
		return err
	}
	b, _ := json.Marshal(pc.LocalDescription())
	a.send(wire.Msg{T: "rc_status", PSID: p.psid, K: "accepted"})
	a.send(wire.Msg{T: "rc_offer", PSID: p.psid, SDP: b})
	if c.Mode == "chat" && c.Role != "viewer" {
		a.plat.ChatShow("Aegis One", c.Operator+" from IT support started a chat. Your screen is not shared. Type your reply below.")
	}
	a.event(c.Session, "peer_joined", c.Operator, fmt.Sprintf("%s joined as %s (%s)", c.Operator, c.Role, wire.ModeText(p.mode)))
	a.updateBanner()
	a.sendState()
	return nil
}

// recoverPeer tries an ICE restart when the network path breaks (Wi-Fi change, VPN reconnect,
// NAT rebinding), so the session survives without asking the user again. The DTLS association
// and the data channels stay as they are; only the network path is renegotiated.
func (a *Agent) recoverPeer(p *peer) {
	if !p.recovering.CompareAndSwap(false, true) {
		return
	}
	defer p.recovering.Store(false)
	time.Sleep(3 * time.Second) // a short blip often heals by itself
	for try := 1; try <= 3; try++ {
		if a.peerBy(p.psid) != p {
			return // already dropped or replaced
		}
		if p.pc.ConnectionState() == webrtc.PeerConnectionStateConnected {
			return
		}
		offer, err := p.pc.CreateOffer(&webrtc.OfferOptions{ICERestart: true})
		if err == nil {
			err = p.pc.SetLocalDescription(offer)
		}
		if err != nil {
			log.Printf("peer %s: ICE restart %d failed: %v", p.psid, try, err)
		} else {
			b, _ := json.Marshal(p.pc.LocalDescription())
			log.Printf("peer %s (%s): ICE restart %d of 3", p.psid, p.operator, try)
			a.send(wire.Msg{T: "rc_offer", PSID: p.psid, SDP: b})
		}
		for i := 0; i < 20; i++ { // wait up to 10 s for this attempt
			time.Sleep(500 * time.Millisecond)
			if p.pc.ConnectionState() == webrtc.PeerConnectionStateConnected {
				log.Printf("peer %s (%s): reconnected", p.psid, p.operator)
				p.needKey.Store(true)
				return
			}
		}
	}
	a.drop(p.psid, wire.ClosePeerFailed, p.operator+" could not reconnect")
}

func (a *Agent) curSession() *session {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sess
}

func (a *Agent) peerBy(psid string) *peer {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sess == nil {
		return nil
	}
	return a.sess.peers[psid]
}

func (a *Agent) onAnswer(m wire.Msg) {
	p := a.peerBy(m.PSID)
	if p == nil {
		return
	}
	var sd webrtc.SessionDescription
	if err := json.Unmarshal(m.SDP, &sd); err != nil {
		log.Printf("bad answer: %v", err)
		return
	}
	if err := p.pc.SetRemoteDescription(sd); err != nil {
		log.Printf("set answer: %v", err)
	}
}

func (a *Agent) onICE(m wire.Msg) {
	p := a.peerBy(m.PSID)
	if p == nil {
		return
	}
	var ci webrtc.ICECandidateInit
	if err := json.Unmarshal(m.C, &ci); err == nil {
		_ = p.pc.AddICECandidate(ci)
	}
}

func (a *Agent) onClose(m wire.Msg) {
	a.mu.Lock()
	s := a.sess
	var p *peer
	if s != nil {
		p = s.peers[m.PSID]
	}
	a.mu.Unlock()
	if p == nil {
		return
	}
	code := m.Close
	if code == "" {
		code = wire.CloseOperatorEnded
	}
	if m.End && s.ctl == p.psid {
		why := "Ended by " + p.operator
		if code == wire.CloseConsoleGone {
			why = p.operator + "'s console disconnected"
		}
		a.endAll(code, why)
	} else {
		a.drop(p.psid, code, p.operator+" left the session")
	}
}

/* ---------------- data channel messages ---------------- */

type ctlMsg struct {
	K    string `json:"k"`
	Mode string `json:"mode,omitempty"`
	On   bool   `json:"on,omitempty"`
	To   string `json:"to,omitempty"`
	FPS  int    `json:"fps,omitempty"`
	Q    int    `json:"q,omitempty"`
	C    string `json:"c,omitempty"`
	X    string `json:"x,omitempty"`
}

func sendJSON(dc *webrtc.DataChannel, v any) {
	if dc == nil || dc.ReadyState() != webrtc.DataChannelStateOpen {
		return
	}
	b, _ := json.Marshal(v)
	_ = dc.SendText(string(b))
}

func (a *Agent) notice(p *peer, text string) {
	sendJSON(p.ch["control"], map[string]any{"k": "notice", "text": text})
}

func (a *Agent) onPeerMsg(p *peer, label string, data []byte) {
	a.mu.Lock()
	s := a.sess
	if s == nil || s.peers[p.psid] != p {
		a.mu.Unlock()
		return
	}
	isCtl := s.ctl == p.psid
	a.mu.Unlock()

	switch label {
	case "input", "move":
		if !isCtl || p.mode != "control" { // the agent enforces who may drive the device
			if label == "input" {
				p.dropped++
				if p.dropped == 1 || p.dropped%25 == 0 {
					a.event(s.id, "input_ignored", p.operator, fmt.Sprintf("input from %s ignored (%s)", p.operator, map[bool]string{true: "view only", false: "viewer"}[isCtl]))
				}
			}
			return
		}
		var ev platform.InputEvent
		if json.Unmarshal(data, &ev) != nil {
			return
		}
		a.mu.Lock()
		s.lastInput = time.Now()
		a.mu.Unlock()
		if err := a.plat.Input(ev); err != nil {
			n := a.inputFails.Add(1)
			if n == 1 || n%50 == 0 {
				log.Printf("input not applied (%d times): %s: %v", n, ev.K, err)
			}
			if ev.K != "move" {
				a.notice(p, "Input not applied: "+err.Error())
			}
		} else if a.inputOK.Add(1) == 1 {
			log.Printf("input: first %s event from %s applied", ev.K, p.operator)
		}
	case "chat":
		var m ctlMsg
		if json.Unmarshal(data, &m) != nil || strings.TrimSpace(m.X) == "" {
			return
		}
		text := m.X
		if len(text) > 500 {
			text = text[:500]
		}
		a.plat.ChatShow(p.operator, text)
		a.plat.Notify("New message from " + p.operator + " in the chat window")
		a.forEach(func(q *peer) {
			if q != p {
				sendJSON(q.ch["chat"], map[string]any{"who": p.operator, "x": text})
			}
		})
	case "shell":
		var m ctlMsg
		if json.Unmarshal(data, &m) != nil {
			return
		}
		go a.runShell(s, p, isCtl, m.C)
	case "control":
		var m ctlMsg
		if json.Unmarshal(data, &m) != nil {
			return
		}
		a.onControl(s, p, isCtl, m)
	}
}

func (a *Agent) forEach(f func(*peer)) {
	a.mu.Lock()
	var ps []*peer
	if a.sess != nil {
		for _, p := range a.sess.peers {
			ps = append(ps, p)
		}
	}
	a.mu.Unlock()
	for _, p := range ps {
		f(p)
	}
}

// askAction shows a fresh consent prompt for an escalation, once per session and controller.
func (a *Agent) askAction(s *session, p *peer, action string, lines []string) bool {
	a.mu.Lock()
	if !s.policy.PerActionConsent || s.approved[action] {
		a.mu.Unlock()
		return true
	}
	a.mu.Unlock()
	if !s.asking.CompareAndSwap(false, true) {
		a.notice(p, "The user is already answering a request.")
		return false
	}
	defer s.asking.Store(false)
	code := wire.VerifyCode(s.id + action + p.psid)
	sendJSON(p.ch["control"], map[string]any{"k": "consent_wait", "action": action, "code": code})
	ok := a.plat.Consent(platform.ConsentRequest{Title: "IT support asks for more access", Operator: p.operator, Action: action,
		Lines: append(lines, "", "Verification code: "+code), Timeout: 60 * time.Second})
	a.event(s.id, "consent_"+map[bool]string{true: "granted", false: "declined"}[ok], p.operator, action)
	sendJSON(p.ch["control"], map[string]any{"k": "consent_result", "action": action, "ok": ok})
	if ok {
		a.mu.Lock()
		s.approved[action] = true
		a.mu.Unlock()
	}
	return ok
}

func (a *Agent) runShell(s *session, p *peer, isCtl bool, cmd string) {
	out := func(t string) { sendJSON(p.ch["shell"], map[string]any{"out": t}) }
	switch {
	case !isCtl:
		out("Access denied: only the controller can run commands.\n\n")
		return
	case !s.policy.ShellAllowed:
		out("The command line is turned off by policy.\n\n")
		return
	}
	if !a.askAction(s, p, "shell", []string{p.operator + " wants to run commands on this computer.",
		a.shellRights() + " Every command is recorded in the audit log."}) {
		out("The user did not allow the command line.\n\n")
		return
	}
	a.event(s.id, "shell_command", p.operator, cmd)
	res, err := a.plat.Shell(cmd, 30*time.Second)
	if len(res) > 64*1024 {
		res = res[:64*1024] + "\n[output truncated]"
	}
	if err != nil && res == "" {
		res = err.Error()
	}
	out(strings.TrimRight(res, "\r\n") + "\n\n")
}

func (a *Agent) onControl(s *session, p *peer, isCtl bool, m ctlMsg) {
	switch m.K {
	case "keyframe":
		p.needKey.Store(true)
		s.vkey.Store(true)
	case "video": // the browser cannot play the video track: send this viewer JPEG tiles
		if !m.On && p.videoOn.Swap(false) {
			p.needKey.Store(true)
			log.Printf("video: %s fell back to JPEG tiles", p.operator)
		}
	case "quality":
		a.mu.Lock()
		if m.FPS >= 2 && m.FPS <= 30 {
			s.fps = m.FPS
		}
		if m.Q >= 30 && m.Q <= 90 {
			s.enc.Quality = m.Q
		}
		a.mu.Unlock()
	case "mode":
		if !isCtl || (m.Mode != "view" && m.Mode != "control") {
			return
		}
		if m.Mode == "control" {
			go func() {
				if !a.askAction(s, p, "control", []string{p.operator + " asks to take control of your mouse and keyboard.",
					"You will see their actions on your screen."}) {
					a.notice(p, "The user did not allow full control. The session stays view only.")
					return
				}
				p.mode = "control"
				a.event(s.id, "mode", p.operator, "Full control")
				a.roster()
				a.updateBanner()
			}()
			return
		}
		p.mode = "view"
		a.plat.ReleaseKeys()
		a.event(s.id, "mode", p.operator, "View only")
		a.roster()
		a.updateBanner()
	case "privacy":
		if !isCtl {
			return
		}
		if !s.policy.PrivacyAllowed {
			a.notice(p, "Privacy mode is turned off by policy.")
			return
		}
		locked, err := a.plat.Privacy(m.On)
		a.mu.Lock()
		s.privacy = m.On
		a.mu.Unlock()
		msg := map[bool]string{true: "Privacy mode on: the end user's screen is hidden", false: "Privacy mode off"}[m.On]
		if m.On && !locked && err != nil {
			msg += ". " + err.Error()
		} else if m.On && locked {
			msg += " and local input is locked"
		}
		a.event(s.id, "privacy", p.operator, msg)
		a.notice(p, msg)
		a.roster()
		a.updateBanner()
	case "sas":
		if !isCtl || p.mode != "control" {
			return
		}
		if err := a.plat.SendSAS(); err != nil {
			a.notice(p, err.Error())
		}
	case "reboot":
		if !isCtl {
			return
		}
		if !a.cfg.AllowReboot || !s.policy.RebootAllowed {
			a.notice(p, "Restart is turned off for this device (policy or agent setting).")
			return
		}
		go func() {
			if !a.askAction(s, p, "reboot", []string{p.operator + " wants to restart this computer.", "Save your work first. The restart starts 30 seconds after you allow it."}) {
				a.notice(p, "The user did not allow the restart.")
				return
			}
			a.event(s.id, "reboot", p.operator, "restart in 30 seconds")
			if err := a.plat.Reboot(); err != nil {
				a.notice(p, "Restart failed: "+err.Error())
				return
			}
			a.endAll(wire.CloseOperatorEnded, "The device is restarting")
		}()
	case "pass":
		if !isCtl {
			return
		}
		a.mu.Lock()
		n := s.peers[m.To]
		if n != nil {
			s.ctl, n.role, n.mode, p.role, p.mode = n.psid, "controller", "view", "viewer", "view"
			s.approved = map[string]bool{} // approvals were given for the previous controller
		}
		a.mu.Unlock()
		if n != nil {
			a.plat.ReleaseKeys()
			a.event(s.id, "control_passed", p.operator, p.operator+" passed control to "+n.operator)
			a.roster()
			a.updateBanner()
			a.sendState()
		}
	case "reqctl":
		if isCtl {
			return
		}
		a.mu.Lock()
		c := s.peers[s.ctl]
		a.mu.Unlock()
		if c != nil {
			sendJSON(c.ch["control"], map[string]any{"k": "reqctl", "tab": p.psid, "operator": p.operator})
		}
	case "deny_req":
		if q := a.peerBy(m.To); isCtl && q != nil {
			sendJSON(q.ch["control"], map[string]any{"k": "req_denied"})
		}
	case "end":
		if isCtl {
			a.endAll(wire.CloseOperatorEnded, "Ended by "+p.operator)
		}
	}
}

/* ---------------- roster, banner, limits, teardown ---------------- */

func (a *Agent) roster() {
	a.mu.Lock()
	s := a.sess
	if s == nil {
		a.mu.Unlock()
		return
	}
	var people []map[string]any
	for _, p := range s.peers {
		people = append(people, map[string]any{"id": p.psid, "tab": p.psid, "operator": p.operator, "role": map[bool]string{true: "controller", false: "viewer"}[p.psid == s.ctl], "mode": p.mode})
	}
	msg := map[string]any{"k": "roster", "session": s.id, "people": people, "privacy": s.privacy}
	ps := make([]*peer, 0, len(s.peers))
	for _, p := range s.peers {
		ps = append(ps, p)
	}
	a.mu.Unlock()
	for _, p := range ps {
		sendJSON(p.ch["control"], msg)
	}
}

func (a *Agent) updateBanner() {
	a.mu.Lock()
	s := a.sess
	if s == nil {
		a.mu.Unlock()
		return
	}
	c := s.peers[s.ctl]
	viewers := len(s.peers) - 1
	text := "Remote session in progress"
	if c != nil {
		text += " · " + c.operator + " · " + map[string]string{"control": "Full control", "chat": "Chat only"}[c.mode]
		if c.mode == "view" {
			text += "View only"
		}
	}
	if viewers > 0 {
		text += fmt.Sprintf(" · %d watching", viewers)
	}
	if s.policy.Record {
		text += " · Recorded"
	}
	if s.privacy {
		text += " · Screen hidden"
	}
	a.mu.Unlock()
	a.plat.Indicator(text, func() { a.endAll(wire.CloseUserEnded, "Ended by the end user") })
}

func (a *Agent) limits(s *session) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
		}
		a.mu.Lock()
		idle := time.Since(s.lastInput)
		age := time.Since(s.started)
		pol := s.policy
		a.mu.Unlock()
		if pol.MaxSec > 0 && age > time.Duration(pol.MaxSec)*time.Second {
			a.endAll(wire.CloseMaxDuration, fmt.Sprintf("The session reached its %d-minute limit", pol.MaxSec/60))
			return
		}
		if pol.IdleSec > 0 && idle > time.Duration(pol.IdleSec)*time.Second {
			a.endAll(wire.CloseIdleTimeout, fmt.Sprintf("Ended after %d minutes without activity", pol.IdleSec/60))
			return
		}
	}
}

func (a *Agent) drop(psid, code, why string) {
	a.mu.Lock()
	s := a.sess
	if s == nil {
		a.mu.Unlock()
		return
	}
	p := s.peers[psid]
	if p == nil {
		a.mu.Unlock()
		return
	}
	if psid == s.ctl {
		a.mu.Unlock()
		a.endAll(code, "The controller ("+p.operator+") left the session")
		return
	}
	delete(s.peers, psid)
	a.mu.Unlock()
	go p.pc.Close()
	a.event(s.id, "peer_left", p.operator, why)
	a.roster()
	a.updateBanner()
	a.sendState()
}

// endAll ends the session for everyone and cleans up the endpoint.
func (a *Agent) endAll(code, reason string) {
	a.mu.Lock()
	s := a.sess
	if s == nil {
		a.mu.Unlock()
		return
	}
	a.sess = nil
	close(s.stop)
	peers := make([]*peer, 0, len(s.peers))
	for _, p := range s.peers {
		peers = append(peers, p)
	}
	a.mu.Unlock()
	if s.rec != nil {
		s.rec.close()
	}
	if s.venc != nil {
		go s.venc.Close()
	}
	for _, p := range peers {
		sendJSON(p.ch["control"], map[string]any{"k": "ended", "reason": reason, "close": code})
	}
	time.AfterFunc(400*time.Millisecond, func() { // let the "ended" message arrive first
		for _, p := range peers {
			p.pc.Close()
		}
	})
	a.plat.ReleaseKeys()
	var done []string
	if s.privacy {
		_, _ = a.plat.Privacy(false)
		done = append(done, "privacy screen removed")
	}
	if s.policy.ClearClipboardOnEnd {
		if err := a.plat.ClearClipboard(); err == nil {
			done = append(done, "clipboard cleared")
		}
	}
	if s.policy.LockOnEnd {
		if err := a.plat.Lock(); err == nil {
			done = append(done, "workstation locked")
		}
	}
	a.plat.HideIndicator()
	a.plat.Notify("The remote session has ended.")
	a.plat.ChatShow("Aegis One", "The remote session has ended ("+reason+").")
	a.event(s.id, "session_ended", "", reason+" ("+code+")"+map[bool]string{true: " · cleanup: " + strings.Join(done, ", "), false: ""}[len(done) > 0])
	a.sendState()
}

/* ---------------- screen streaming ---------------- */

func (a *Agent) stream(s *session) {
	var frames, bytes, capFails int
	lastLog := time.Now()
	for {
		a.mu.Lock()
		fps := s.fps
		if s.venc != nil && fps < a.cfg.VideoFPS {
			fps = a.cfg.VideoFPS
		}
		a.mu.Unlock()
		select {
		case <-s.stop:
			return
		case <-time.After(time.Second / time.Duration(fps)):
		}
		var targets, vtargets []*peer
		congested := false
		a.forEach(func(p *peer) {
			if p.mode == "chat" {
				return
			}
			if p.video != nil && p.videoOn.Load() && !s.vfailed && p.pc.ConnectionState() == webrtc.PeerConnectionStateConnected {
				vtargets = append(vtargets, p)
				return
			}
			if !p.screenOpen.Load() {
				return
			}
			dc := p.ch["screen"]
			if dc.ReadyState() != webrtc.DataChannelStateOpen {
				return
			}
			if dc.BufferedAmount() > 4<<20 { // the viewer cannot keep up; wait
				congested = true
			}
			targets = append(targets, p)
		})
		if (len(targets) == 0 || congested) && len(vtargets) == 0 {
			continue
		}
		img, err := a.plat.Capture()
		if err != nil {
			capFails++
			if capFails == 1 || capFails%50 == 0 {
				log.Printf("screen capture failed (%d times): %v", capFails, err)
			}
			if s.capErr != err.Error() {
				s.capErr = err.Error()
				a.forEach(func(p *peer) {
					a.notice(p, "Screen not readable right now (for example a UAC prompt or the lock screen): "+err.Error())
				})
			}
			continue
		}
		if capFails > 0 {
			log.Printf("screen capture working again after %d failures", capFails)
			capFails = 0
		}
		s.capErr = ""
		if len(vtargets) > 0 {
			a.pushVideo(s, img, vtargets)
		}
		if len(targets) == 0 && s.rec == nil {
			continue
		}
		a.mu.Lock()
		var keyed []*peer
		for _, p := range targets {
			if p.needKey.Swap(false) {
				keyed = append(keyed, p)
			}
		}
		var full [][]byte
		now := time.Now()
		recKey := s.rec != nil && s.rec.wantKey(now)
		if len(keyed) > 0 || recKey {
			full = s.enc.Full(img)
		}
		diff := s.enc.Encode(img, false)
		a.mu.Unlock()
		if s.rec != nil {
			if recKey {
				s.rec.add(full, true, now)
			} else {
				s.rec.add(diff, false, now)
			}
		}
		for _, p := range keyed {
			n, err := sendAll(p.ch["screen"], full)
			b := img.Bounds()
			log.Printf("screen: keyframe %dx%d sent to %s (%d messages, %d KB)%s", b.Dx(), b.Dy(), p.operator, len(full), n/1024, errText(err))
			bytes += n
		}
		if diff != nil {
			frames++
			for _, p := range targets {
				n, err := sendAll(p.ch["screen"], diff)
				bytes += n
				if err != nil {
					log.Printf("screen: send to %s failed: %v", p.operator, err)
				}
			}
		}
		if time.Since(lastLog) > 30*time.Second {
			log.Printf("screen: %d changed frames, %d KB sent in the last %ds", frames, bytes/1024, int(time.Since(lastLog).Seconds()))
			frames, bytes, lastLog = 0, 0, time.Now()
		}
	}
}

func errText(err error) string {
	if err != nil {
		return " · error: " + err.Error()
	}
	return ""
}

// pushVideo feeds one frame to the H.264 encoder and forwards whatever access units are ready
// to every viewer playing the video track.
func (a *Agent) pushVideo(s *session, img *image.RGBA, vt []*peer) {
	b := img.Bounds()
	w, h := b.Dx()&^1, b.Dy()&^1
	restart := s.venc == nil
	if s.venc != nil {
		if ew, eh := s.venc.Size(); ew != w || eh != h {
			restart = true // resolution changed
		} else if s.venc.Err() != nil {
			log.Printf("video: %v", s.venc.Err())
			restart = true
		}
	}
	if !restart && s.vkey.Load() && time.Since(s.vlastKey) > 2*time.Second {
		restart = true // a fresh encoder starts with an IDR frame
	}
	if restart {
		if s.venc != nil {
			go s.venc.Close()
			s.venc = nil
		}
		enc, err := video.Start(a.ffmpeg, w, h, a.cfg.VideoFPS, a.cfg.VideoFPS*4, a.cfg.VideoKbps)
		if err != nil {
			log.Printf("video: encoder failed (%v); switching every viewer to JPEG tiles", err)
			s.vfailed = true
			for _, p := range vt {
				p.needKey.Store(true)
			}
			return
		}
		s.venc, s.vlastKey = enc, time.Now()
		s.vkey.Store(false)
		log.Printf("video: H.264 encoder %dx%d at %d fps, %d kbps", w, h, a.cfg.VideoFPS, a.cfg.VideoKbps)
	}
	if err := s.venc.Push(img); err != nil {
		log.Printf("video: push: %v", err)
		return
	}
	dur := time.Second / time.Duration(a.cfg.VideoFPS)
	for {
		select {
		case au, ok := <-s.venc.Frames():
			if !ok {
				return
			}
			for _, p := range vt {
				_ = p.video.WriteSample(media.Sample{Data: au, Duration: dur})
			}
		default:
			return
		}
	}
}

func sendAll(dc *webrtc.DataChannel, msgs [][]byte) (int, error) {
	n := 0
	for _, m := range msgs {
		if err := dc.Send(m); err != nil {
			return n, err
		}
		n += len(m)
	}
	return n, nil
}

func localIP() string {
	conn, err := net.Dial("udp", "192.0.2.1:9") // no packet is sent; picks the outbound interface
	if err != nil {
		h, _ := os.Hostname()
		return h
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}
