//go:build windows

package platform

import (
	"errors"
	"fmt"
	"image"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// This prototype runs in the signed-in user's session so it can capture the desktop and inject
// input directly. The production agent runs as a SYSTEM service with a per-session helper,
// which is also what Ctrl+Alt+Del (SendSAS) and the logon screen need.

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	gdi32    = windows.NewLazySystemDLL("gdi32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	wtsapi32 = windows.NewLazySystemDLL("wtsapi32.dll")
	sasDLL   = windows.NewLazySystemDLL("sas.dll")

	pOpenInputDesktop     = user32.NewProc("OpenInputDesktop")
	pSetThreadDesktop     = user32.NewProc("SetThreadDesktop")
	pCloseDesktop         = user32.NewProc("CloseDesktop")
	pGetUserObjectInfoW   = user32.NewProc("GetUserObjectInformationW")
	pWTSQuerySessionInfoW = wtsapi32.NewProc("WTSQuerySessionInformationW")
	pSendSAS              = sasDLL.NewProc("SendSAS")

	pGetDC                   = user32.NewProc("GetDC")
	pReleaseDC               = user32.NewProc("ReleaseDC")
	pGetSystemMetrics        = user32.NewProc("GetSystemMetrics")
	pSendInput               = user32.NewProc("SendInput")
	pGetCursorInfo           = user32.NewProc("GetCursorInfo")
	pGetIconInfo             = user32.NewProc("GetIconInfo")
	pDrawIconEx              = user32.NewProc("DrawIconEx")
	pMessageBoxTimeoutW      = user32.NewProc("MessageBoxTimeoutW")
	pRegisterClassExW        = user32.NewProc("RegisterClassExW")
	pCreateWindowExW         = user32.NewProc("CreateWindowExW")
	pDefWindowProcW          = user32.NewProc("DefWindowProcW")
	pGetMessageW             = user32.NewProc("GetMessageW")
	pTranslateMessage        = user32.NewProc("TranslateMessage")
	pDispatchMessageW        = user32.NewProc("DispatchMessageW")
	pPostThreadMessageW      = user32.NewProc("PostThreadMessageW")
	pShowWindow              = user32.NewProc("ShowWindow")
	pDestroyWindow           = user32.NewProc("DestroyWindow")
	pInvalidateRect          = user32.NewProc("InvalidateRect")
	pBeginPaint              = user32.NewProc("BeginPaint")
	pEndPaint                = user32.NewProc("EndPaint")
	pFillRect                = user32.NewProc("FillRect")
	pDrawTextW               = user32.NewProc("DrawTextW")
	pSetWindowDisplayAff     = user32.NewProc("SetWindowDisplayAffinity")
	pSetLayeredWindowAttribs = user32.NewProc("SetLayeredWindowAttributes")
	pSetWindowPos            = user32.NewProc("SetWindowPos")
	pLockWorkStation         = user32.NewProc("LockWorkStation")
	pBlockInput              = user32.NewProc("BlockInput")
	pOpenClipboard           = user32.NewProc("OpenClipboard")
	pEmptyClipboard          = user32.NewProc("EmptyClipboard")
	pCloseClipboard          = user32.NewProc("CloseClipboard")
	pSetDpiCtx               = user32.NewProc("SetProcessDpiAwarenessContext")
	pSetDPIAware             = user32.NewProc("SetProcessDPIAware")
	pLoadCursorW             = user32.NewProc("LoadCursorW")
	pGetWindowTextW          = user32.NewProc("GetWindowTextW")
	pGetWindowTextLengthW    = user32.NewProc("GetWindowTextLengthW")
	pSetWindowTextW          = user32.NewProc("SetWindowTextW")
	pSendMessageW            = user32.NewProc("SendMessageW")
	pIsDialogMessageW        = user32.NewProc("IsDialogMessageW")
	pSetForegroundWindow     = user32.NewProc("SetForegroundWindow")
	pSetFocus                = user32.NewProc("SetFocus")

	pCreateCompatibleDC     = gdi32.NewProc("CreateCompatibleDC")
	pCreateCompatibleBitmap = gdi32.NewProc("CreateCompatibleBitmap")
	pSelectObject           = gdi32.NewProc("SelectObject")
	pDeleteObject           = gdi32.NewProc("DeleteObject")
	pDeleteDC               = gdi32.NewProc("DeleteDC")
	pBitBlt                 = gdi32.NewProc("BitBlt")
	pCreateDIBSection       = gdi32.NewProc("CreateDIBSection")
	pGdiFlush               = gdi32.NewProc("GdiFlush")
	pCreateSolidBrush       = gdi32.NewProc("CreateSolidBrush")
	pSetTextColor           = gdi32.NewProc("SetTextColor")
	pSetBkMode              = gdi32.NewProc("SetBkMode")
	pCreateFontW            = gdi32.NewProc("CreateFontW")

	pGetCurrentThreadId = kernel32.NewProc("GetCurrentThreadId")
)

const (
	smCxScreen = 0
	smCyScreen = 1

	srcCopy    = 0x00CC0020
	captureBlt = 0x40000000

	inputMouse    = 0
	inputKeyboard = 1

	mouseMove       = 0x0001
	mouseLeftDown   = 0x0002
	mouseLeftUp     = 0x0004
	mouseRightDown  = 0x0008
	mouseRightUp    = 0x0010
	mouseMiddleDown = 0x0020
	mouseMiddleUp   = 0x0040
	mouseWheel      = 0x0800
	mouseHWheel     = 0x1000
	mouseAbsolute   = 0x8000

	keyExtended = 0x0001
	keyUp       = 0x0002
	keyUnicode  = 0x0004

	wmPaint       = 0x000F
	wmDestroy     = 0x0002
	wmLButtonUp   = 0x0202
	wmApp         = 0x8000
	wsPopup       = 0x80000000
	wsExTopmost   = 0x00000008
	wsExToolwin   = 0x00000080
	wsExNoActive  = 0x08000000
	wsExLayered   = 0x00080000
	wsExTransp    = 0x00000020
	swShowNoAct   = 4
	wdaExcludeCap = 0x00000011
	lwaAlpha      = 0x2
	dtCenter      = 0x1
	dtVCenter     = 0x4
	dtSingleLine  = 0x20
	dtWordBreak   = 0x10
	dtEndEllipsis = 0x8000
	transparentBk = 1

	mbYesNo        = 0x00000004
	mbIconQuestion = 0x00000020
	mbDefButton2   = 0x00000100
	mbSystemModal  = 0x00001000
	mbSetFg        = 0x00010000
	mbTopmost      = 0x00040000
	idYes          = 6
	mbTimedOut     = 32000

	cursorShowing = 0x00000001
	diNormal      = 0x0003
)

type point struct{ X, Y int32 }
type rect struct{ Left, Top, Right, Bottom int32 }

type mouseInput struct {
	Dx, Dy                int32
	MouseData, Flags, Tim uint32
	ExtraInfo             uintptr
}
type keybdInput struct {
	Vk, Scan   uint16
	Flags, Tim uint32
	ExtraInfo  uintptr
	_          [8]byte // pad to the size of the INPUT union
}
type inputM struct {
	Type uint32
	_    [4]byte
	Mi   mouseInput
}
type inputK struct {
	Type uint32
	_    [4]byte
	Ki   keybdInput
}

type cursorInfo struct {
	Size    uint32
	Flags   uint32
	HCursor uintptr
	Pt      point
}
type iconInfo struct {
	FIcon              int32
	XHotspot, YHotspot uint32
	HbmMask, HbmColor  uintptr
}
type bitmapInfoHeader struct {
	Size                         uint32
	Width, Height                int32
	Planes, BitCount             uint16
	Compression, SizeImage       uint32
	XPelsPerMeter, YPelsPerMeter int32
	ClrUsed, ClrImportant        uint32
}
type msgT struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
	_       uint32
}
type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   uintptr
	Icon       uintptr
	Cursor     uintptr
	Background uintptr
	MenuName   *uint16
	ClassName  *uint16
	IconSm     uintptr
}
type paintStruct struct {
	Hdc       uintptr
	Erase     int32
	RcPaint   rect
	Restore   int32
	IncUpdate int32
	Reserved  [32]byte
}

func init() {
	if unsafe.Sizeof(inputM{}) != 40 || unsafe.Sizeof(inputK{}) != 40 {
		panic("unexpected INPUT size; this build supports 64-bit Windows only")
	}
}

// Windows is the Win32 implementation.
type Windows struct {
	capMu   sync.Mutex
	scrDC   uintptr
	memDC   uintptr
	bmp     uintptr
	w, h    int
	bits    unsafe.Pointer // pixel memory of the DIB section the screen is copied into
	inputCh chan func()
	capCh   chan func()
	oldObj  uintptr // the DC's original bitmap, restored when the capture objects are freed
	held    map[uint16]bool
	ui      *uiThread
	capDesk desktopFollower // the capture thread's desktop
	dx      *dxgiCapture    // DXGI Desktop Duplication, when CaptureMode is "dxgi"
	system  bool            // running as LocalSystem (service helper): follow the secure desktop
	dxFails int
	inDesk  desktopFollower // the input thread's desktop
}

// desktopFollower keeps one OS thread on the current input desktop. When Windows switches to the
// secure desktop (UAC prompt, lock or logon screen, Ctrl+Alt+Del screen) only a SYSTEM process
// can open it; as the service helper the agent follows it, so the operator keeps seeing and
// controlling the screen. In the user session (foreground mode) the switch fails and the thread
// stays on the normal desktop, as before.
type desktopFollower struct {
	h    uintptr
	name string
}

const (
	desktopAll = 0x01FF // DESKTOP_* access rights the capture and input threads need
	uoiName    = 2
)

func desktopName(h uintptr) string {
	var buf [128]uint16
	var need uint32
	if r, _, _ := pGetUserObjectInfoW.Call(h, uoiName, uintptr(unsafe.Pointer(&buf[0])), unsafe.Sizeof(buf), uintptr(unsafe.Pointer(&need))); r == 0 {
		return ""
	}
	return windows.UTF16ToString(buf[:])
}

// follow moves the calling thread to the input desktop if it changed; true when it switched.
// The thread must own no windows or hooks (true for the capture and input threads).
func (d *desktopFollower) follow() bool {
	h, _, _ := pOpenInputDesktop.Call(0, 0, desktopAll)
	if h == 0 {
		return false
	}
	name := desktopName(h)
	if name == "" || name == d.name {
		pCloseDesktop.Call(h)
		return false
	}
	if r, _, _ := pSetThreadDesktop.Call(h); r == 0 {
		pCloseDesktop.Call(h)
		return false
	}
	if d.h != 0 {
		pCloseDesktop.Call(d.h)
	}
	d.h, d.name = h, name
	return true
}

// isSystem reports whether the process runs as LocalSystem (the service helper).
func isSystem() bool {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	return err == nil && u.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
}

func New() (Platform, error) {
	// capture and input must use physical pixels
	if pSetDpiCtx.Find() == nil {
		pSetDpiCtx.Call(^uintptr(3)) // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 (-4)
	} else {
		pSetDPIAware.Call()
	}
	p := &Windows{inputCh: make(chan func(), 256), capCh: make(chan func()), held: map[uint16]bool{}, system: isSystem()}
	// GDI device contexts belong to the thread that created them, so all capture work runs on
	// one locked OS thread (goroutines otherwise move between threads).
	go func() {
		runtime.LockOSThread()
		for f := range p.capCh {
			f()
		}
	}()
	// One OS thread owns BlockInput and every SendInput call: Windows only lets the thread
	// that blocked input keep injecting it, which is what privacy mode needs.
	go func() {
		runtime.LockOSThread()
		for f := range p.inputCh {
			f()
		}
	}()
	p.ui = startUI()
	return p, nil
}

func (p *Windows) Name() string { return "windows" }
func (p *Windows) OS() string {
	v := windows.RtlGetVersion()
	return fmt.Sprintf("Windows %d.%d build %d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
}

// ActiveUser is the user signed in to this process's session, "" at the logon screen. It asks
// Windows instead of reading USERNAME, which would say SYSTEM for the service helper.
func (p *Windows) ActiveUser() string {
	var buf *uint16
	var n uint32
	const wtsCurrentSession, wtsUserName = 0xFFFFFFFF, 5
	if r, _, _ := pWTSQuerySessionInfoW.Call(0, wtsCurrentSession, wtsUserName, uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&n))); r == 0 || buf == nil {
		if isSystem() {
			return ""
		}
		return os.Getenv("USERNAME")
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(buf)))
	return windows.UTF16PtrToString(buf)
}

func (p *Windows) ScreenSize() (int, int) {
	w, _, _ := pGetSystemMetrics.Call(smCxScreen)
	h, _, _ := pGetSystemMetrics.Call(smCyScreen)
	return int(w), int(h)
}

// Capture grabs the primary monitor with GDI, including the mouse pointer. Windows marked
// WDA_EXCLUDEFROMCAPTURE (our banner and privacy screen) are left out by the OS.
func (p *Windows) Capture() (*image.RGBA, error) {
	type res struct {
		img *image.RGBA
		err error
	}
	ch := make(chan res, 1)
	p.capCh <- func() { i, e := p.capture(); ch <- res{i, e} }
	r := <-ch
	return r.img, r.err
}

func (p *Windows) capture() (*image.RGBA, error) {
	p.capMu.Lock()
	defer p.capMu.Unlock()
	if p.system && p.capDesk.follow() {
		p.freeCapture() // device contexts belong to the previous desktop
		if p.dx != nil {
			p.dx.close()
			p.dx = nil
		}
		log.Printf("[platform] capture follows the input desktop: %s", p.capDesk.name)
	}
	if CaptureMode == "dxgi" && p.dxFails < 5 {
		if p.dx == nil {
			d, err := newDXGI()
			if err != nil {
				p.dxFails++
				log.Printf("[platform] DXGI capture unavailable (%v); using GDI", err)
			} else {
				p.dx = d
				log.Printf("[platform] DXGI Desktop Duplication %dx%d", d.w, d.h)
			}
		}
		if p.dx != nil {
			img, err := p.dx.frame()
			if err == nil {
				p.dxFails = 0
				return img, nil
			}
			if errors.Is(err, errAccessLost) { // recreate on the next frame
				p.dx.close()
				p.dx = nil
			} else {
				p.dxFails++
				log.Printf("[platform] DXGI frame: %v; using GDI for this frame", err)
				if p.dxFails >= 5 {
					p.dx.close()
					p.dx = nil
					log.Printf("[platform] DXGI disabled after repeated failures; GDI from now on")
				}
			}
		}
	}
	w, h := p.ScreenSize()
	if w <= 0 || h <= 0 {
		return nil, errors.New("no screen")
	}
	if p.scrDC == 0 {
		p.scrDC, _, _ = pGetDC.Call(0)
		if p.scrDC == 0 {
			return nil, errors.New("GetDC failed")
		}
	}
	if p.memDC == 0 || w != p.w || h != p.h {
		// A top-down 32-bit DIB section: BitBlt writes straight into memory we can read, so no
		// GetDIBits call (which fails on some RDP / Enhanced Session and high-resolution desktops).
		p.freeCapture()
		p.scrDC, _, _ = pGetDC.Call(0)
		p.memDC, _, _ = pCreateCompatibleDC.Call(p.scrDC)
		bi := bitmapInfoHeader{Width: int32(w), Height: -int32(h), Planes: 1, BitCount: 32}
		bi.Size = uint32(unsafe.Sizeof(bi))
		var bits unsafe.Pointer
		p.bmp, _, _ = pCreateDIBSection.Call(p.scrDC, uintptr(unsafe.Pointer(&bi)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
		if p.memDC == 0 || p.bmp == 0 || bits == nil {
			p.freeCapture()
			return nil, fmt.Errorf("could not create a %dx%d capture bitmap", w, h)
		}
		p.bits = bits
		p.oldObj, _, _ = pSelectObject.Call(p.memDC, p.bmp)
		p.w, p.h = w, h
	}
	if r, _, err := pBitBlt.Call(p.memDC, 0, 0, uintptr(w), uintptr(h), p.scrDC, 0, 0, srcCopy|captureBlt); r == 0 {
		// the secure desktop (UAC, lock screen) cannot be read from the user session
		p.freeCapture()
		return nil, fmt.Errorf("BitBlt: %v", err)
	}
	var ci cursorInfo
	ci.Size = uint32(unsafe.Sizeof(ci))
	if r, _, _ := pGetCursorInfo.Call(uintptr(unsafe.Pointer(&ci))); r != 0 && ci.Flags&cursorShowing != 0 {
		var ii iconInfo
		if r, _, _ := pGetIconInfo.Call(ci.HCursor, uintptr(unsafe.Pointer(&ii))); r != 0 {
			pDrawIconEx.Call(p.memDC, uintptr(ci.Pt.X-int32(ii.XHotspot)), uintptr(ci.Pt.Y-int32(ii.YHotspot)), ci.HCursor, 0, 0, 0, 0, diNormal)
			if ii.HbmMask != 0 {
				pDeleteObject.Call(ii.HbmMask)
			}
			if ii.HbmColor != 0 {
				pDeleteObject.Call(ii.HbmColor)
			}
		}
	}
	pGdiFlush.Call() // make sure GDI has finished writing the DIB before we read it
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	src, dst := unsafe.Slice((*byte)(p.bits), w*h*4), img.Pix
	for i := 0; i < len(src); i += 4 { // BGRA -> RGBA
		dst[i], dst[i+1], dst[i+2], dst[i+3] = src[i+2], src[i+1], src[i], 255
	}
	return img, nil
}

func (p *Windows) freeCapture() {
	if p.memDC != 0 && p.oldObj != 0 {
		pSelectObject.Call(p.memDC, p.oldObj)
		p.oldObj = 0
	}
	if p.bmp != 0 {
		pDeleteObject.Call(p.bmp)
		p.bmp = 0
		p.bits = nil
	}
	if p.memDC != 0 {
		pDeleteDC.Call(p.memDC)
		p.memDC = 0
	}
	if p.scrDC != 0 {
		pReleaseDC.Call(0, p.scrDC)
		p.scrDC = 0
	}
	p.w, p.h = 0, 0
}

func (p *Windows) onInputThread(f func() error) error {
	done := make(chan error, 1)
	select {
	case p.inputCh <- func() {
		if p.system {
			p.inDesk.follow()
		}
		done <- f()
	}:
	case <-time.After(2 * time.Second):
		return errors.New("input thread busy")
	}
	return <-done
}

func sendMouse(flags uint32, dx, dy int32, data uint32) error {
	in := inputM{Type: inputMouse, Mi: mouseInput{Dx: dx, Dy: dy, MouseData: data, Flags: flags}}
	if r, _, err := pSendInput.Call(1, uintptr(unsafe.Pointer(&in)), unsafe.Sizeof(in)); r != 1 {
		return fmt.Errorf("SendInput: %v (input blocked by a higher-integrity window such as UAC?)", err)
	}
	return nil
}

func sendKey(vk, scan uint16, flags uint32) error {
	in := inputK{Type: inputKeyboard, Ki: keybdInput{Vk: vk, Scan: scan, Flags: flags}}
	if r, _, err := pSendInput.Call(1, uintptr(unsafe.Pointer(&in)), unsafe.Sizeof(in)); r != 1 {
		return fmt.Errorf("SendInput: %v", err)
	}
	return nil
}

func (p *Windows) Input(ev InputEvent) error {
	return p.onInputThread(func() error {
		abs := func() (int32, int32) { return int32(clamp01(ev.X) * 65535), int32(clamp01(ev.Y) * 65535) }
		switch ev.K {
		case "move":
			x, y := abs()
			return sendMouse(mouseMove|mouseAbsolute, x, y, 0)
		case "down", "up":
			x, y := abs()
			if err := sendMouse(mouseMove|mouseAbsolute, x, y, 0); err != nil {
				return err
			}
			var f uint32
			switch ev.B {
			case 1:
				f = map[bool]uint32{true: mouseMiddleDown, false: mouseMiddleUp}[ev.K == "down"]
			case 2:
				f = map[bool]uint32{true: mouseRightDown, false: mouseRightUp}[ev.K == "down"]
			default:
				f = map[bool]uint32{true: mouseLeftDown, false: mouseLeftUp}[ev.K == "down"]
			}
			return sendMouse(f, 0, 0, 0)
		case "wheel":
			if ev.DY != 0 {
				if err := sendMouse(mouseWheel, 0, 0, uint32(int32(-ev.DY*1.2))); err != nil {
					return err
				}
			}
			if ev.DX != 0 {
				return sendMouse(mouseHWheel, 0, 0, uint32(int32(ev.DX*1.2)))
			}
			return nil
		case "key":
			return p.key(ev)
		}
		return nil
	})
}

// key types printable characters as Unicode (so the user's keyboard layout does not matter)
// and sends shortcuts and special keys as virtual keys.
func (p *Windows) key(ev InputEvent) error {
	r := []rune(ev.Key)
	printable := len(r) == 1 && r[0] >= 0x20 && !ev.Ctrl && !ev.Alt && !ev.Meta
	if printable {
		if !ev.Down {
			return nil
		}
		for _, u := range utf16.Encode(r) {
			if err := sendKey(0, u, keyUnicode); err != nil {
				return err
			}
			if err := sendKey(0, u, keyUnicode|keyUp); err != nil {
				return err
			}
		}
		return nil
	}
	vk, ext := vkFor(ev.Code)
	if vk == 0 {
		return nil
	}
	f := uint32(0)
	if ext {
		f |= keyExtended
	}
	if !ev.Down {
		f |= keyUp
		delete(p.held, vk)
	} else {
		p.held[vk] = true
	}
	return sendKey(vk, 0, f)
}

func (p *Windows) ReleaseKeys() {
	_ = p.onInputThread(func() error {
		for vk := range p.held {
			_ = sendKey(vk, 0, keyUp)
		}
		p.held = map[uint16]bool{}
		return nil
	})
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

var vkTable = map[string]uint16{
	"Enter": 0x0D, "Backspace": 0x08, "Tab": 0x09, "Escape": 0x1B, "Space": 0x20,
	"ArrowLeft": 0x25, "ArrowUp": 0x26, "ArrowRight": 0x27, "ArrowDown": 0x28,
	"Insert": 0x2D, "Delete": 0x2E, "Home": 0x24, "End": 0x23, "PageUp": 0x21, "PageDown": 0x22,
	"ShiftLeft": 0xA0, "ShiftRight": 0xA1, "ControlLeft": 0xA2, "ControlRight": 0xA3,
	"AltLeft": 0xA4, "AltRight": 0xA5, "MetaLeft": 0x5B, "MetaRight": 0x5C, "ContextMenu": 0x5D,
	"CapsLock": 0x14, "NumLock": 0x90, "ScrollLock": 0x91, "PrintScreen": 0x2C, "Pause": 0x13,
	"Minus": 0xBD, "Equal": 0xBB, "BracketLeft": 0xDB, "BracketRight": 0xDD, "Backslash": 0xDC,
	"Semicolon": 0xBA, "Quote": 0xDE, "Comma": 0xBC, "Period": 0xBE, "Slash": 0xBF, "Backquote": 0xC0,
	"NumpadEnter": 0x0D, "NumpadAdd": 0x6B, "NumpadSubtract": 0x6D, "NumpadMultiply": 0x6A,
	"NumpadDivide": 0x6F, "NumpadDecimal": 0x6E,
}
var extended = map[string]bool{"ArrowLeft": true, "ArrowUp": true, "ArrowRight": true, "ArrowDown": true,
	"Insert": true, "Delete": true, "Home": true, "End": true, "PageUp": true, "PageDown": true,
	"ControlRight": true, "AltRight": true, "MetaLeft": true, "MetaRight": true, "ContextMenu": true,
	"NumpadEnter": true, "NumpadDivide": true, "PrintScreen": true}

func vkFor(code string) (uint16, bool) {
	if vk, ok := vkTable[code]; ok {
		return vk, extended[code]
	}
	switch {
	case strings.HasPrefix(code, "Key") && len(code) == 4:
		return uint16(code[3]), false
	case strings.HasPrefix(code, "Digit") && len(code) == 6:
		return uint16(code[5]), false
	case strings.HasPrefix(code, "Numpad") && len(code) == 7 && code[6] >= '0' && code[6] <= '9':
		return 0x60 + uint16(code[6]-'0'), false
	case strings.HasPrefix(code, "F") && len(code) <= 3:
		var n int
		if _, err := fmt.Sscanf(code, "F%d", &n); err == nil && n >= 1 && n <= 24 {
			return 0x70 + uint16(n-1), false
		}
	}
	return 0, false
}

// Consent shows a system-modal Yes/No prompt. "No" is the default button and no answer within
// the timeout counts as declined.
func (p *Windows) Consent(req ConsentRequest) bool {
	text := strings.Join(req.Lines, "\r\n") + "\r\n\r\nAllow this? Yes = Allow, No = Deny"
	done := make(chan bool, 1)
	go func() {
		runtime.LockOSThread()
		t, _ := windows.UTF16PtrFromString(text)
		c, _ := windows.UTF16PtrFromString("Aegis One · " + req.Title)
		r, _, _ := pMessageBoxTimeoutW.Call(0, uintptr(unsafe.Pointer(t)), uintptr(unsafe.Pointer(c)),
			mbYesNo|mbIconQuestion|mbDefButton2|mbSystemModal|mbSetFg|mbTopmost, 0, uintptr(req.Timeout.Milliseconds()))
		done <- r == idYes
	}()
	return <-done
}

func (p *Windows) Indicator(text string, onEnd func()) { p.ui.banner(text, onEnd) }
func (p *Windows) HideIndicator()                      { p.ui.hideBanner() }
func (p *Windows) Notify(text string)                  { p.ui.flash(text) }
func (p *Windows) ChatShow(who, text string)           { p.ui.chatShow(who, text) }
func (p *Windows) ChatClose()                          { p.ui.chatClose() }
func (p *Windows) OnChat(fn func(text string))         { p.ui.mu.Lock(); p.ui.onChat = fn; p.ui.mu.Unlock() }

// Privacy shows a black screen to the end user. The window is excluded from capture, so the
// operator still sees the desktop, and it is click-through so remote input reaches the apps.
// Local keyboard and mouse are locked with BlockInput when the agent is elevated.
func (p *Windows) Privacy(on bool) (bool, error) {
	p.ui.privacy(on)
	locked := false
	err := p.onInputThread(func() error {
		v := uintptr(0)
		if on {
			v = 1
		}
		if r, _, e := pBlockInput.Call(v); r == 0 && on {
			return fmt.Errorf("local input not locked: %v (run the agent as administrator)", e)
		}
		locked = on
		return nil
	})
	return locked, err
}

func (p *Windows) ClearClipboard() error {
	if r, _, err := pOpenClipboard.Call(0); r == 0 {
		return err
	}
	defer pCloseClipboard.Call()
	if r, _, err := pEmptyClipboard.Call(); r == 0 {
		return err
	}
	return nil
}

func (p *Windows) Lock() error {
	if r, _, err := pLockWorkStation.Call(); r == 0 {
		return err
	}
	return nil
}

func (p *Windows) Reboot() error {
	return exec.Command("shutdown.exe", "/r", "/t", "30", "/c", "Restart requested by IT support through Aegis One").Run()
}

// SendSAS generates a real Ctrl+Alt+Del. Windows allows it only from a SYSTEM process with the
// SoftwareSASGeneration policy set, which "service install" does.
func (p *Windows) SendSAS() error {
	if !isSystem() {
		return errors.New("Ctrl+Alt+Del needs the agent installed as a service (aegis-rc-agent service install)")
	}
	if err := pSendSAS.Find(); err != nil {
		return fmt.Errorf("sas.dll: %w", err)
	}
	pSendSAS.Call(0) // FALSE: the caller is a service, not a user
	return nil
}

func (p *Windows) Shell(cmd string, timeout time.Duration) (string, error) {
	c := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", cmd)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	type res struct {
		out []byte
		err error
	}
	ch := make(chan res, 1)
	go func() { o, e := c.CombinedOutput(); ch <- res{o, e} }()
	select {
	case r := <-ch:
		return string(r.out), r.err
	case <-time.After(timeout):
		if c.Process != nil {
			_ = c.Process.Kill()
		}
		return "", fmt.Errorf("command timed out after %s", timeout)
	}
}

/* ---------- UI thread: session banner and privacy screen ---------- */

type uiThread struct {
	tid        uint32
	mu         sync.Mutex
	queue      []func()
	bannerH    uintptr
	privH      uintptr
	text       string
	flashText  string
	flashUntil time.Time
	onEnd      func()
	bannerW    int32
	gold, dark uintptr
	black      uintptr
	font       uintptr
	fontN      uintptr
	chatH      uintptr // end-user chat window and its controls
	chatHist   uintptr
	chatIn     uintptr
	onChat     func(string)
}

var theUI *uiThread

func startUI() *uiThread {
	u := &uiThread{}
	theUI = u
	ready := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		r, _, _ := pGetCurrentThreadId.Call()
		u.tid = uint32(r)
		u.gold, _, _ = pCreateSolidBrush.Call(0x006BA1C6) // #C6A16B as COLORREF (BGR)
		u.dark, _, _ = pCreateSolidBrush.Call(0x0027211D) // #1D2127
		u.black, _, _ = pCreateSolidBrush.Call(0x00000000)
		face, _ := windows.UTF16PtrFromString("Segoe UI")
		u.font, _, _ = pCreateFontW.Call(uintptr(^uint32(17)+1), 0, 0, 0, 600, 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(face)))
		u.fontN, _, _ = pCreateFontW.Call(uintptr(^uint32(15)+1), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(face)))
		cb := syscall.NewCallback(wndProc)
		arrow, _, _ := pLoadCursorW.Call(0, 32512)
		for _, name := range []string{"AegisRCBanner", "AegisRCPrivacy", "AegisRCChat"} {
			n, _ := windows.UTF16PtrFromString(name)
			wc := wndClassEx{WndProc: cb, ClassName: n, Cursor: arrow}
			if name == "AegisRCChat" {
				wc.Background = 16 // COLOR_BTNFACE + 1
			}
			wc.Size = uint32(unsafe.Sizeof(wc))
			pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
		}
		close(ready)
		var m msgT
		for {
			r, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
			if int32(r) <= 0 {
				return
			}
			if m.Hwnd == 0 && m.Message == wmApp {
				u.mu.Lock()
				q := u.queue
				u.queue = nil
				u.mu.Unlock()
				for _, f := range q {
					f()
				}
				continue
			}
			if u.chatH != 0 { // Enter sends and Tab moves between controls in the chat window
				if r, _, _ := pIsDialogMessageW.Call(u.chatH, uintptr(unsafe.Pointer(&m))); r != 0 {
					continue
				}
			}
			pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
			pDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
		}
	}()
	<-ready
	go func() { // repaint once a flashed message expires
		for range time.Tick(time.Second) {
			u.do(func() {
				if !u.flashUntil.IsZero() && time.Now().After(u.flashUntil) {
					u.flashUntil = time.Time{}
					u.repaint()
				}
			})
		}
	}()
	return u
}

func (u *uiThread) do(f func()) {
	u.mu.Lock()
	u.queue = append(u.queue, f)
	u.mu.Unlock()
	pPostThreadMessageW.Call(uintptr(u.tid), wmApp, 0, 0)
}

func (u *uiThread) repaint() {
	if u.bannerH != 0 {
		pInvalidateRect.Call(u.bannerH, 0, 1)
	}
}

func screenW() int32 { w, _, _ := pGetSystemMetrics.Call(smCxScreen); return int32(w) }
func screenH() int32 { h, _, _ := pGetSystemMetrics.Call(smCyScreen); return int32(h) }

func (u *uiThread) banner(text string, onEnd func()) {
	u.do(func() {
		u.text, u.onEnd = text, onEnd
		if u.bannerH == 0 {
			w := min(screenW()*7/10, 980)
			u.bannerW = w
			cls, _ := windows.UTF16PtrFromString("AegisRCBanner")
			h, _, _ := pCreateWindowExW.Call(wsExTopmost|wsExToolwin|wsExNoActive, uintptr(unsafe.Pointer(cls)), 0, wsPopup,
				uintptr((screenW()-w)/2), 0, uintptr(w), 34, 0, 0, 0, 0)
			u.bannerH = h
			pSetWindowDisplayAff.Call(h, wdaExcludeCap) // the operator does not need to see it
			pShowWindow.Call(h, swShowNoAct)
		}
		u.repaint()
	})
}

func (u *uiThread) hideBanner() {
	u.do(func() {
		if u.bannerH != 0 {
			pDestroyWindow.Call(u.bannerH)
			u.bannerH = 0
		}
		u.onEnd = nil
	})
}

func (u *uiThread) flash(text string) {
	u.do(func() {
		u.flashText, u.flashUntil = text, time.Now().Add(12*time.Second)
		u.repaint()
	})
}

func (u *uiThread) privacy(on bool) {
	u.do(func() {
		if on && u.privH == 0 {
			cls, _ := windows.UTF16PtrFromString("AegisRCPrivacy")
			h, _, _ := pCreateWindowExW.Call(wsExTopmost|wsExToolwin|wsExNoActive|wsExLayered|wsExTransp, uintptr(unsafe.Pointer(cls)), 0, wsPopup,
				0, 0, uintptr(screenW()), uintptr(screenH()), 0, 0, 0, 0)
			u.privH = h
			pSetLayeredWindowAttribs.Call(h, 0, 255, lwaAlpha)
			pSetWindowDisplayAff.Call(h, wdaExcludeCap)
			pShowWindow.Call(h, swShowNoAct)
			if u.bannerH != 0 { // keep the banner above the privacy screen
				pSetWindowPos.Call(u.bannerH, ^uintptr(0), 0, 0, 0, 0, 0x0001|0x0002|0x0010)
			}
		} else if !on && u.privH != 0 {
			pDestroyWindow.Call(u.privH)
			u.privH = 0
		}
	})
}

func utf16p(s string) *uint16 { p, _ := windows.UTF16PtrFromString(s); return p }

const (
	wmClose     = 0x0010
	wmCommand   = 0x0111
	wmSetFont   = 0x0030
	emSetSel    = 0x00B1
	emReplace   = 0x00C2
	idOK        = 1
	idSend      = 2001
	wsChild     = 0x40000000
	wsVisible   = 0x10000000
	wsBorder    = 0x00800000
	wsVScroll   = 0x00200000
	wsTabStop   = 0x00010000
	wsCaption   = 0x00C00000
	wsSysMenu   = 0x00080000
	esMultiline = 0x0004
	esReadOnly  = 0x0800
	esAutoV     = 0x0040
	esAutoH     = 0x0080
	bsDefPush   = 0x0001
	swShow      = 5
	swHide      = 0
)

// chatShow adds a line to the end user's chat window, creating and showing it if needed.
func (u *uiThread) chatShow(who, text string) {
	u.do(func() {
		if u.chatH == 0 {
			const w, h = 400, 440
			cls := utf16p("AegisRCChat")
			u.chatH, _, _ = pCreateWindowExW.Call(wsExTopmost|wsExToolwin, uintptr(unsafe.Pointer(cls)), uintptr(unsafe.Pointer(utf16p("Aegis One · Chat with IT support"))),
				wsCaption|wsSysMenu, uintptr(screenW()-w-24), uintptr(screenH()-h-64), w, h, 0, 0, 0, 0)
			mk := func(class string, style uintptr, x, y, cw, ch int32, id uintptr, title string) uintptr {
				hwnd, _, _ := pCreateWindowExW.Call(0, uintptr(unsafe.Pointer(utf16p(class))), uintptr(unsafe.Pointer(utf16p(title))), wsChild|wsVisible|style,
					uintptr(x), uintptr(y), uintptr(cw), uintptr(ch), u.chatH, id, 0, 0)
				pSendMessageW.Call(hwnd, wmSetFont, u.fontN, 1)
				return hwnd
			}
			u.chatHist = mk("EDIT", wsBorder|wsVScroll|esMultiline|esReadOnly|esAutoV, 12, 12, 360, 330, 0, "")
			u.chatIn = mk("EDIT", wsBorder|wsTabStop|esAutoH, 12, 352, 270, 30, 0, "")
			mk("BUTTON", wsTabStop|bsDefPush, 290, 351, 82, 32, idSend, "Send")
		}
		line := who + "  " + time.Now().Format("15:04") + "\r\n" + strings.ReplaceAll(text, "\n", "\r\n") + "\r\n\r\n"
		n, _, _ := pGetWindowTextLengthW.Call(u.chatHist)
		pSendMessageW.Call(u.chatHist, emSetSel, n, n)
		pSendMessageW.Call(u.chatHist, emReplace, 0, uintptr(unsafe.Pointer(utf16p(line))))
		pShowWindow.Call(u.chatH, swShowNoAct)
	})
}

func (u *uiThread) chatClose() {
	u.do(func() {
		if u.chatH != 0 {
			pDestroyWindow.Call(u.chatH)
			u.chatH, u.chatHist, u.chatIn = 0, 0, 0
		}
	})
}

func (u *uiThread) chatSend() {
	n, _, _ := pGetWindowTextLengthW.Call(u.chatIn)
	if n == 0 {
		return
	}
	buf := make([]uint16, n+1)
	pGetWindowTextW.Call(u.chatIn, uintptr(unsafe.Pointer(&buf[0])), n+1)
	text := strings.TrimSpace(windows.UTF16ToString(buf))
	pSetWindowTextW.Call(u.chatIn, uintptr(unsafe.Pointer(utf16p(""))))
	if text == "" {
		return
	}
	line := "You  " + time.Now().Format("15:04") + "\r\n" + text + "\r\n\r\n"
	l, _, _ := pGetWindowTextLengthW.Call(u.chatHist)
	pSendMessageW.Call(u.chatHist, emSetSel, l, l)
	pSendMessageW.Call(u.chatHist, emReplace, 0, uintptr(unsafe.Pointer(utf16p(line))))
	u.mu.Lock()
	fn := u.onChat
	u.mu.Unlock()
	if fn != nil {
		go fn(text)
	}
}

func wndProc(hwnd, msg, wparam, lparam uintptr) uintptr {
	u := theUI
	if hwnd == u.chatH && u.chatH != 0 {
		switch msg {
		case wmCommand:
			if id := wparam & 0xFFFF; id == idOK || id == idSend {
				u.chatSend()
				pSetFocus.Call(u.chatIn)
				return 0
			}
		case wmClose: // closing only hides it; the next message opens it again
			pShowWindow.Call(hwnd, swHide)
			return 0
		}
		r, _, _ := pDefWindowProcW.Call(hwnd, msg, wparam, lparam)
		return r
	}
	switch msg {
	case wmPaint:
		var ps paintStruct
		hdc, _, _ := pBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		if hwnd == u.bannerH {
			full := rect{0, 0, u.bannerW, 34}
			pFillRect.Call(hdc, uintptr(unsafe.Pointer(&full)), u.gold)
			btn := rect{u.bannerW - 132, 0, u.bannerW, 34}
			pFillRect.Call(hdc, uintptr(unsafe.Pointer(&btn)), u.dark)
			pSetBkMode.Call(hdc, transparentBk)
			pSelectObject.Call(hdc, u.font)
			txt := u.text
			if !u.flashUntil.IsZero() && time.Now().Before(u.flashUntil) {
				txt = u.flashText
			}
			pSetTextColor.Call(hdc, 0x0027211D)
			tr := rect{14, 0, u.bannerW - 140, 34}
			pDrawTextW.Call(hdc, uintptr(unsafe.Pointer(utf16p(txt))), ^uintptr(0), uintptr(unsafe.Pointer(&tr)), dtVCenter|dtSingleLine|dtEndEllipsis)
			pSetTextColor.Call(hdc, 0x00FFFFFF)
			pDrawTextW.Call(hdc, uintptr(unsafe.Pointer(utf16p("End session  ✕"))), ^uintptr(0), uintptr(unsafe.Pointer(&btn)), dtCenter|dtVCenter|dtSingleLine)
		} else if hwnd == u.privH {
			full := rect{0, 0, screenW(), screenH()}
			pFillRect.Call(hdc, uintptr(unsafe.Pointer(&full)), u.black)
			pSetBkMode.Call(hdc, transparentBk)
			pSelectObject.Call(hdc, u.font)
			pSetTextColor.Call(hdc, 0x00EDEAE8)
			tr := rect{0, screenH()/2 - 40, screenW(), screenH()/2 + 40}
			pDrawTextW.Call(hdc, uintptr(unsafe.Pointer(utf16p("IT support is working on this computer. Your screen is hidden for privacy until they finish."))), ^uintptr(0), uintptr(unsafe.Pointer(&tr)), dtCenter|dtWordBreak)
		}
		pEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		return 0
	case wmLButtonUp:
		if hwnd == u.bannerH && int32(int16(lparam&0xFFFF)) >= u.bannerW-132 && u.onEnd != nil {
			go u.onEnd()
		}
		return 0
	case wmDestroy:
		return 0
	}
	r, _, _ := pDefWindowProcW.Call(hwnd, msg, wparam, lparam)
	return r
}
