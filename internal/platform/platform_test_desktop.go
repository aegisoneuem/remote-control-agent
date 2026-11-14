//go:build !windows

package platform

import (
	"errors"
	"fmt"
	"image"
	"image/color"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// TestDesktop is a synthetic desktop used on non-Windows builds so the server, agent and
// console can be tested end to end. Input changes what it draws, so effects are visible in the
// streamed screen. Consent is answered by AEGIS_TEST_CONSENT (accept, deny, or a comma list
// such as "accept,deny" consumed in order).
type TestDesktop struct {
	mu       sync.Mutex
	w, h     int
	cx, cy   int
	marks    [][2]int
	text     []rune
	privacy  bool
	answers  []string
	banner   string
	clip     string
	locked   bool
	inputs   int
	keysDown map[string]bool
	onChat   func(string)
}

func New() (Platform, error) {
	a := strings.Split(os.Getenv("AEGIS_TEST_CONSENT"), ",")
	return &TestDesktop{w: 1280, h: 720, cx: 640, cy: 360, answers: a, clip: "secret clipboard text", keysDown: map[string]bool{}}, nil
}

func plog(format string, a ...any) { log.Printf("[platform] "+format, a...) }

func (t *TestDesktop) Name() string           { return "test-desktop" }
func (t *TestDesktop) OS() string             { return "Test desktop (non-Windows build)" }
func (t *TestDesktop) ActiveUser() string     { return "test.user" }
func (t *TestDesktop) ScreenSize() (int, int) { return t.w, t.h }

func (t *TestDesktop) Capture() (*image.RGBA, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	img := image.NewRGBA(image.Rect(0, 0, t.w, t.h))
	for y := 0; y < t.h; y++ {
		c := color.RGBA{uint8(30 + y*20/t.h), uint8(48 + y*20/t.h), uint8(70 + y*30/t.h), 255}
		for x := 0; x < t.w; x++ {
			img.SetRGBA(x, y, c)
		}
	}
	fill(img, 160, 90, 700, 380, color.RGBA{255, 255, 255, 255}) // "notepad" window
	fill(img, 160, 90, 700, 122, color.RGBA{230, 235, 242, 255}) // title bar
	for i := range t.text {                                      // each typed character is a block
		x, y := 176+(i%40)*13, 136+(i/40)*22
		fill(img, x, y, x+10, y+16, color.RGBA{30, 41, 59, 255})
	}
	sec := time.Now().Second() // a moving clock bar
	fill(img, 0, t.h-36, t.w, t.h, color.RGBA{17, 20, 24, 255})
	fill(img, 20, t.h-26, 20+sec*20, t.h-12, color.RGBA{198, 161, 107, 255})
	for _, m := range t.marks {
		fill(img, m[0]-6, m[1]-6, m[0]+6, m[1]+6, color.RGBA{180, 35, 24, 255})
	}
	fill(img, t.cx-2, t.cy-2, t.cx+3, t.cy+3, color.RGBA{255, 255, 255, 255}) // pointer
	return img, nil
}

func fill(img *image.RGBA, x0, y0, x1, y1 int, c color.RGBA) {
	b := img.Bounds()
	for y := max(y0, b.Min.Y); y < min(y1, b.Max.Y); y++ {
		for x := max(x0, b.Min.X); x < min(x1, b.Max.X); x++ {
			img.SetRGBA(x, y, c)
		}
	}
}

func (t *TestDesktop) Input(ev InputEvent) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.inputs++
	switch ev.K {
	case "move":
		t.cx, t.cy = int(ev.X*float64(t.w)), int(ev.Y*float64(t.h))
	case "down":
		t.cx, t.cy = int(ev.X*float64(t.w)), int(ev.Y*float64(t.h))
		t.marks = append(t.marks, [2]int{t.cx, t.cy})
		plog("input mouse down button=%d at %.3f,%.3f", ev.B, ev.X, ev.Y)
	case "up":
	case "wheel":
		plog("input wheel dy=%.0f", ev.DY)
	case "key":
		if ev.Down {
			t.keysDown[ev.Code] = true
		} else {
			delete(t.keysDown, ev.Code)
		}
		if ev.Down && len([]rune(ev.Key)) == 1 && !ev.Ctrl && !ev.Alt && !ev.Meta {
			t.text = append(t.text, []rune(ev.Key)...)
			plog("input text %q (typed so far: %q)", ev.Key, string(t.text))
		} else if ev.Down {
			plog("input key %s ctrl=%v alt=%v shift=%v", ev.Code, ev.Ctrl, ev.Alt, ev.Shift)
		}
	}
	return nil
}

func (t *TestDesktop) ReleaseKeys() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.keysDown) > 0 {
		plog("released %d held keys", len(t.keysDown))
	}
	t.keysDown = map[string]bool{}
}

func (t *TestDesktop) Consent(req ConsentRequest) bool {
	t.mu.Lock()
	ans := "accept"
	if len(t.answers) > 0 && t.answers[0] != "" {
		ans = t.answers[0]
		if len(t.answers) > 1 {
			t.answers = t.answers[1:]
		}
	}
	t.mu.Unlock()
	plog("consent prompt %q for %s:\n    %s\n    -> %s", req.Title, req.Action, strings.Join(req.Lines, "\n    "), ans)
	time.Sleep(600 * time.Millisecond) // a person takes a moment to read it
	return ans == "accept"
}

func (t *TestDesktop) Indicator(text string, onEnd func()) {
	t.mu.Lock()
	changed := t.banner != text
	t.banner = text
	t.mu.Unlock()
	if changed {
		plog("banner: %s", text)
	}
}
func (t *TestDesktop) HideIndicator()     { plog("banner hidden") }
func (t *TestDesktop) Notify(text string) { plog("notify end user: %s", text) }

// ChatShow logs the line; AEGIS_TEST_REPLY makes the "user" answer each operator message.
func (t *TestDesktop) ChatShow(who, text string) {
	plog("chat window: %s: %s", who, text)
	t.mu.Lock()
	fn := t.onChat
	t.mu.Unlock()
	if r := os.Getenv("AEGIS_TEST_REPLY"); r != "" && fn != nil && who != "Aegis One" {
		go func() { time.Sleep(700 * time.Millisecond); plog("chat window: user replied %q", r); fn(r) }()
	}
}
func (t *TestDesktop) ChatClose()                  { plog("chat window closed") }
func (t *TestDesktop) OnChat(fn func(text string)) { t.mu.Lock(); t.onChat = fn; t.mu.Unlock() }

func (t *TestDesktop) Privacy(on bool) (bool, error) {
	t.mu.Lock()
	t.privacy = on
	t.mu.Unlock()
	plog("privacy screen on=%v", on)
	return on, nil
}
func (t *TestDesktop) ClearClipboard() error {
	t.mu.Lock()
	t.clip = ""
	t.mu.Unlock()
	plog("clipboard cleared")
	return nil
}
func (t *TestDesktop) Lock() error   { plog("workstation locked"); return nil }
func (t *TestDesktop) Reboot() error { plog("reboot requested"); return nil }
func (t *TestDesktop) SendSAS() error {
	return errors.New("Ctrl+Alt+Del needs the agent service running as SYSTEM")
}
func (t *TestDesktop) Shell(cmd string, timeout time.Duration) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	switch strings.ToLower(strings.TrimSpace(cmd)) {
	case "whoami":
		return "test-host\\test.user\n", nil
	case "hostname":
		h, _ := os.Hostname()
		return h + "\n", nil
	case "get-clipboard":
		return t.clip + "\n", nil
	}
	return fmt.Sprintf("(test desktop) ran: %s\n", cmd), nil
}
