// Package platform is everything the agent needs from the operating system: screen capture,
// input injection, the end-user consent prompt, the session banner and privacy screen, and
// session-end cleanup. The Windows build talks to Win32 directly (no CGO); other builds use a
// test desktop so the full protocol can be exercised in CI.
package platform

import (
	"image"
	"time"
)

// CaptureMode selects the Windows capture method: "gdi" (default) or "dxgi" (DXGI Desktop
// Duplication, GPU-based; falls back to GDI whenever it is unavailable). Set before New.
var CaptureMode = "gdi"

// InputEvent arrives from the controller over the "input" and "move" data channels.
// X and Y are fractions (0..1) of the captured screen, so any viewer size maps correctly.
type InputEvent struct {
	K     string  `json:"k"` // move, down, up, wheel, key
	X     float64 `json:"x"`
	Y     float64 `json:"y"`
	B     int     `json:"b"` // 0 left, 1 middle, 2 right
	DX    float64 `json:"dx"`
	DY    float64 `json:"dy"`
	Key   string  `json:"key"`
	Code  string  `json:"code"`
	Down  bool    `json:"down"`
	Ctrl  bool    `json:"ctrl"`
	Alt   bool    `json:"alt"`
	Shift bool    `json:"shift"`
	Meta  bool    `json:"meta"`
}

// ConsentRequest is everything the end user is told before deciding.
type ConsentRequest struct {
	Title    string        // e.g. "Remote support request"
	Operator string        // who is asking
	Action   string        // "session", "control", "shell", "reboot", "join"
	Lines    []string      // plain-language details: session type, reason, recording, limits, code
	Timeout  time.Duration // no answer = declined
}

// Platform is implemented per operating system.
type Platform interface {
	Name() string
	OS() string
	ActiveUser() string // signed-in interactive user, "" when nobody is signed in
	ScreenSize() (int, int)
	Capture() (*image.RGBA, error)
	Input(ev InputEvent) error
	ReleaseKeys() // release any modifier still held by the operator
	Consent(req ConsentRequest) bool
	Indicator(text string, onEnd func()) // show or update the session banner
	HideIndicator()
	Notify(text string) // short message to the end user on the session banner
	// Chat shows a line in the end user's chat window (opening it if needed); OnChat receives
	// what the user types back.
	ChatShow(who, text string)
	ChatClose()
	OnChat(fn func(text string))
	Privacy(on bool) (inputLocked bool, err error)
	ClearClipboard() error
	Lock() error
	Reboot() error
	SendSAS() error
	Shell(cmd string, timeout time.Duration) (string, error)
}
