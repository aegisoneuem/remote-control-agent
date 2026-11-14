// Package wire holds the messages exchanged between the Aegis RC server, the agent and the
// console, and the signed open_rc kickoff command.
//
// The prototype carries these as JSON over WebSocket (TLS 1.3 only). The production wire is
// the agent-track proto (aegis_one_proto): open_rc becomes a signed Command and the signaling
// messages ride the RCSession bidi RPC. Field names here mirror that design so the mapping is
// one to one.
package wire

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Policy is set on the server and travels inside the signed command, so the agent enforces
// exactly what the server approved and an operator cannot change it from the console.
type Policy struct {
	Consent             string `json:"consent"`            // "always" or "unattended_if_no_user"
	PerActionConsent    bool   `json:"per_action_consent"` // ask again for control, command line, reboot
	Record              bool   `json:"record"`             // session must be recorded
	IdleSec             int    `json:"idle_s"`             // end after this long without operator input
	MaxSec              int    `json:"max_s"`              // hard limit on session length
	ClearClipboardOnEnd bool   `json:"clear_clipboard_on_end"`
	LockOnEnd           bool   `json:"lock_on_end"`
	PrivacyAllowed      bool   `json:"privacy_allowed"` // operator may blank the endpoint screen
	ShellAllowed        bool   `json:"shell_allowed"`
	RebootAllowed       bool   `json:"reboot_allowed"`
	RetentionDays       int    `json:"retention_days"` // encrypted recordings are deleted after this many days
}

// DefaultPolicy is consent-first: nothing starts until the signed-in user accepts.
func DefaultPolicy() Policy {
	return Policy{Consent: "always", PerActionConsent: true, Record: true, IdleSec: 900, MaxSec: 7200,
		ClearClipboardOnEnd: true, LockOnEnd: false, PrivacyAllowed: true, ShellAllowed: true, RebootAllowed: false, RetentionDays: 30}
}

// OpenRC is the kickoff command. The server signs its exact JSON bytes; the agent verifies them
// before doing anything else.
type OpenRC struct {
	Type       string `json:"type"`        // always "open_rc"
	SID        string `json:"sid"`         // single-use id for this peer connection
	Session    string `json:"session"`     // remote session id shared by all participants
	Device     string `json:"device"`      // target device name
	Operator   string `json:"operator"`    // display name shown to the end user
	OperatorID string `json:"operator_id"` // stable operator id (audit)
	Role       string `json:"role"`        // "controller" or "viewer"
	Mode       string `json:"mode"`        // "view", "control" or "chat"
	Reason     string `json:"reason"`      // reason or ticket, shown to the end user
	Policy     Policy `json:"policy"`
	Issued     int64  `json:"issued"` // unix milliseconds
	TTL        int    `json:"ttl"`    // seconds the command is valid
	Nonce      string `json:"nonce"`
	KeyID      string `json:"key_id"`
	// ICE servers for this session, including short-lived TURN credentials. Signed with the rest
	// of the command, so a tampered relay cannot redirect the media path.
	ICE []ICEServer `json:"ice,omitempty"`
	// Recording public key (X25519) the agent must encrypt this session's recording for.
	RecKeyID string `json:"rec_key_id,omitempty"`
	RecPub   string `json:"rec_pub,omitempty"`
}

// RecHeader is the wrapped data key of an encrypted recording (see internal/rec).
type RecHeader struct {
	KeyID   string `json:"key_id"`
	EphPub  string `json:"eph_pub"`
	Wrapped string `json:"wrapped"`
}

// RecInfo describes one stored recording for the console.
type RecInfo struct {
	Session    string `json:"session"`
	Device     string `json:"device"`
	Operator   string `json:"operator"`
	Reason     string `json:"reason"`
	Started    string `json:"started"`
	Ended      string `json:"ended,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	Bytes      int64  `json:"bytes"`
	Chunks     int64  `json:"chunks"`
	Status     string `json:"status"`
	Expires    string `json:"expires"`
	W          int    `json:"w"`
	H          int    `json:"h"`
}

// ICEServer is one STUN or TURN entry, in the shape RTCPeerConnection expects.
type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// Close reasons: a fixed list so the console can show a precise message (agent-track console
// question 8). Every rc_deny and every "ended" control message carries one.
const (
	ClosePermissionDenied = "permission_denied"    // server RBAC refused before the user was asked
	CloseReasonRequired   = "reason_required"      // policy requires a reason or ticket
	CloseAgentOffline     = "agent_offline"        // no agent connected for the device
	CloseInvalidCommand   = "invalid_command"      // signature, TTL, replay or device check failed
	CloseDeviceBusy       = "device_busy"          // another session or prompt is in progress
	CloseNoUser           = "no_user"              // nobody signed in and policy requires consent
	CloseUserDeclined     = "user_declined"        // the user said No or did not answer in time
	ClosePeerFailed       = "peer_failed"          // WebRTC could not connect or reconnect
	CloseOperatorEnded    = "operator_ended"       // the controller ended the session
	CloseUserEnded        = "user_ended"           // the user pressed End session on the banner
	CloseIdleTimeout      = "idle_timeout"         // no operator input for policy idle_s
	CloseMaxDuration      = "max_duration"         // policy max_s reached
	CloseConsoleGone      = "console_disconnected" // the operator's console went away
	CloseRateLimited      = "rate_limited"         // too many requests
	CloseInternal         = "internal_error"
)

// Msg is the envelope for every message on every socket. Only the fields a message needs are set.
type Msg struct {
	T string `json:"t"`

	// auth / identity
	Token   string    `json:"token,omitempty"`
	Device  string    `json:"device,omitempty"`
	OS      string    `json:"os,omitempty"`
	User    string    `json:"user,omitempty"`
	IP      string    `json:"ip,omitempty"`
	Version string    `json:"version,omitempty"`
	Caps    []string  `json:"caps,omitempty"`
	Screen  *ScreenSz `json:"screen,omitempty"`

	// session routing
	PSID    string `json:"psid,omitempty"`
	Session string `json:"session,omitempty"`
	Join    string `json:"join,omitempty"`
	Mode    string `json:"mode,omitempty"`
	Reason  string `json:"reason,omitempty"`
	K       string `json:"k,omitempty"`
	Action  string `json:"action,omitempty"`
	Code    string `json:"code,omitempty"`
	Text    string `json:"text,omitempty"`
	End     bool   `json:"end,omitempty"`
	Close   string `json:"close,omitempty"` // one of the Close* reasons

	// signed kickoff
	CmdB64 string `json:"cmd_b64,omitempty"`
	Sig    string `json:"sig,omitempty"`
	KeyID  string `json:"key_id,omitempty"`

	// WebRTC
	SDP json.RawMessage `json:"sdp,omitempty"`
	C   json.RawMessage `json:"c,omitempty"`
	ICE []ICEServer     `json:"ice,omitempty"`

	// encrypted recordings
	N    int64      `json:"n,omitempty"`    // chunk number, or duration in ms on rec_close
	Data string     `json:"data,omitempty"` // base64 chunk (sealed agent -> server, plain server -> console)
	Rec  *RecHeader `json:"rec,omitempty"`
	Recs []RecInfo  `json:"recs,omitempty"`

	// server -> console
	Operator *OperatorInfo  `json:"operator,omitempty"`
	Server   *ServerInfo    `json:"server,omitempty"`
	Policy   *Policy        `json:"policy,omitempty"`
	Agents   []AgentInfo    `json:"agents,omitempty"`
	Audit    []AuditEntry   `json:"audit,omitempty"`
	Session2 *SessionInfo   `json:"sess,omitempty"`
	Extra    map[string]any `json:"extra,omitempty"`
}

type ScreenSz struct {
	W int `json:"w"`
	H int `json:"h"`
}

type OperatorInfo struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Perms []string `json:"perms"`
}

type ServerInfo struct {
	Version    string   `json:"version"`
	TLS        string   `json:"tls"`
	KeyID      string   `json:"key_id"`
	ICEServers []string `json:"ice_servers,omitempty"`
}

type SessionInfo struct {
	ID       string `json:"id"`
	Operator string `json:"operator"`
	Mode     string `json:"mode"`
	People   int    `json:"people"`
	Started  int64  `json:"started"`
	Reason   string `json:"reason"`
}

type AgentInfo struct {
	Device  string       `json:"device"`
	OS      string       `json:"os"`
	User    string       `json:"user"`
	IP      string       `json:"ip"`
	Version string       `json:"version"`
	Caps    []string     `json:"caps"`
	Online  bool         `json:"online"`
	Session *SessionInfo `json:"session,omitempty"`
	Screen  *ScreenSz    `json:"screen,omitempty"`
}

type AuditEntry struct {
	At       string `json:"at"`
	Event    string `json:"event"`
	Operator string `json:"operator,omitempty"`
	Device   string `json:"device,omitempty"`
	Session  string `json:"session,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// KeyID names a public key so agents can trust a set of keys and rotate them.
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:6])
}

// Sign returns the command bytes (base64) and the Ed25519 signature over those exact bytes.
func Sign(priv ed25519.PrivateKey, c OpenRC) (cmdB64, sig string, err error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(raw), base64.StdEncoding.EncodeToString(ed25519.Sign(priv, raw)), nil
}

// ErrBadSignature is returned when the command was not signed by a trusted key.
var ErrBadSignature = errors.New("signature check failed")

// Verify checks the signature with the trusted key set, then decodes and sanity-checks the command.
func Verify(trusted map[string]ed25519.PublicKey, cmdB64, sig, keyID string, now time.Time) (OpenRC, error) {
	var c OpenRC
	pub, ok := trusted[keyID]
	if !ok {
		return c, fmt.Errorf("unknown signing key %q", keyID)
	}
	raw, err := base64.StdEncoding.DecodeString(cmdB64)
	if err != nil {
		return c, ErrBadSignature
	}
	s, err := base64.StdEncoding.DecodeString(sig)
	if err != nil || !ed25519.Verify(pub, raw, s) {
		return c, ErrBadSignature
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, fmt.Errorf("decode command: %w", err)
	}
	if c.Type != "open_rc" || c.KeyID != keyID {
		return c, errors.New("command type or key id mismatch")
	}
	issued := time.UnixMilli(c.Issued)
	if now.Sub(issued) > time.Duration(c.TTL)*time.Second || issued.Sub(now) > 30*time.Second {
		return c, errors.New("command expired")
	}
	return c, nil
}

// VerifyCode is a short code both the operator and the end user see, so the user can confirm by
// phone that the request really comes from the person they are talking to.
func VerifyCode(sid string) string {
	h := sha256.Sum256([]byte("aegis-rc-verify:" + sid))
	n := binary.BigEndian.Uint32(h[:4]) % 1000000
	return fmt.Sprintf("%03d %03d", n/1000, n%1000)
}

// ModeText describes a session type in plain words for the consent prompt.
func ModeText(mode string) string {
	switch mode {
	case "control":
		return "Full control: see your screen and use your mouse and keyboard"
	case "chat":
		return "Chat only: send you messages. Your screen is not shared"
	default:
		return "View only: see your screen. They cannot use your mouse or keyboard"
	}
}
