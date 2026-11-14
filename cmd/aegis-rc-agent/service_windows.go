//go:build windows

package main

// The production agent is a Windows service (LocalSystem, session 0) that does no screen work
// itself: session 0 has no desktop. It supervises a helper, the same executable started with
// "helper", which it launches into the active user session with a copy of its own SYSTEM token.
// Running as SYSTEM inside the user's session lets the helper follow the input desktop onto the
// secure desktop (UAC prompts, the lock and logon screens) and generate Ctrl+Alt+Del, while
// consent prompts, the banner and chat stay on the user's normal desktop.
//
// The service relaunches the helper when it exits, when the active session changes (logon,
// logoff, user switch, RDP/Enhanced Session connect) and after a reboot (automatic start).

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	svcName    = "AegisRC"
	svcDisplay = "Aegis One Remote Control Agent"
	svcDesc    = "Consent-first remote support for Aegis One. Connects outbound to the Aegis RC server over TLS 1.3."
)

func dataDir() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "AegisRC")
}

func programDir() string {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, "AegisRC")
}

// fileConfig is the service's config file. The enrollment token is DPAPI-protected and the
// folder is readable by SYSTEM and Administrators only.
type fileConfig struct {
	settings
	TokenDPAPI string `json:"token_dpapi"`
	TrustText  string `json:"trust"`
}

func protect(b []byte) (string, error) {
	in := windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_LOCAL_MACHINE|windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return "", err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return base64.StdEncoding.EncodeToString(unsafe.Slice(out.Data, out.Size)), nil
}

func unprotect(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) == 0 {
		return "", errors.New("protected token is corrupt")
	}
	in := windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return "", err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return string(unsafe.Slice(out.Data, out.Size)), nil
}

// lockDown gives SYSTEM and Administrators full control and removes everyone else (no
// inheritance from ProgramData, where Users can read).
func lockDown(path string) error {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func loadConfig() (settings, error) {
	var fc fileConfig
	b, err := os.ReadFile(filepath.Join(dataDir(), "agent.json"))
	if err != nil {
		return settings{}, err
	}
	if err := json.Unmarshal(b, &fc); err != nil {
		return settings{}, err
	}
	tok, err := unprotect(fc.TokenDPAPI)
	if err != nil {
		return settings{}, fmt.Errorf("enrollment token: %w", err)
	}
	s := fc.settings
	s.Token, s.Trust = tok, fc.TrustText
	return s, nil
}

/* ---------------- service install / control ---------------- */

func serviceCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("use: service install|uninstall|start|stop|status")
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("open the service manager (run from an elevated prompt): %w", err)
	}
	defer m.Disconnect()
	switch args[0] {
	case "install":
		return install(m, args[1:])
	case "uninstall":
		return uninstall(m)
	case "start", "stop", "status":
		s, err := m.OpenService(svcName)
		if err != nil {
			return fmt.Errorf("service not installed: %w", err)
		}
		defer s.Close()
		switch args[0] {
		case "start":
			return s.Start()
		case "stop":
			_, err := s.Control(svc.Stop)
			return err
		}
		st, err := s.Query()
		if err != nil {
			return err
		}
		fmt.Println(map[svc.State]string{svc.Stopped: "stopped", svc.StartPending: "starting", svc.StopPending: "stopping", svc.Running: "running"}[st.State])
		fmt.Println("logs:", filepath.Join(dataDir(), "logs"))
		return nil
	}
	return fmt.Errorf("unknown service command %q", args[0])
}

func install(m *mgr.Mgr, args []string) error {
	s, _, err := parseFlags(flag.NewFlagSet("install", flag.ContinueOnError), args)
	if err != nil {
		return err
	}
	if _, err := parseTrust(s.Trust); err != nil {
		return err
	}
	if s.Pin == "" && !s.Insecure {
		return errors.New("-pin is required for the service")
	}
	dd := dataDir()
	if err := os.MkdirAll(filepath.Join(dd, "logs"), 0o700); err != nil {
		return err
	}
	if err := lockDown(dd); err != nil {
		return fmt.Errorf("protect %s: %w", dd, err)
	}
	ptok, err := protect([]byte(s.Token))
	if err != nil {
		return fmt.Errorf("protect token: %w", err)
	}
	fc := fileConfig{settings: s, TokenDPAPI: ptok, TrustText: s.Trust}
	b, _ := json.MarshalIndent(fc, "", "  ")
	if err := os.WriteFile(filepath.Join(dd, "agent.json"), b, 0o600); err != nil {
		return err
	}
	// install a copy of the executable under Program Files so the service does not depend on
	// the folder it was installed from
	src, err := os.Executable()
	if err != nil {
		return err
	}
	pd := programDir()
	if err := os.MkdirAll(pd, 0o755); err != nil {
		return err
	}
	exe := filepath.Join(pd, "aegis-rc-agent.exe")
	if !strings.EqualFold(src, exe) {
		if old, err := m.OpenService(svcName); err == nil { // upgrading: stop first so the file is free
			_, _ = old.Control(svc.Stop)
			old.Close()
			time.Sleep(3 * time.Second)
		}
		if err := copyFile(src, exe); err != nil {
			return fmt.Errorf("copy agent to %s: %w", pd, err)
		}
		// H.264 video uses ffmpeg.exe next to the agent, when one was shipped beside it
		if ff := filepath.Join(filepath.Dir(src), "ffmpeg.exe"); fileExists(ff) {
			if err := copyFile(ff, filepath.Join(pd, "ffmpeg.exe")); err != nil {
				fmt.Println("note: could not copy ffmpeg.exe:", err)
			}
		}
	}
	// Allow services to generate Ctrl+Alt+Del (SendSAS); 1 = services only.
	if k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, registry.SET_VALUE); err == nil {
		_ = k.SetDWordValue("SoftwareSASGeneration", 1)
		k.Close()
	}
	sv, err := m.OpenService(svcName)
	if err == nil {
		cfg, _ := sv.Config()
		cfg.BinaryPathName = `"` + exe + `"`
		if err := sv.UpdateConfig(cfg); err != nil {
			sv.Close()
			return err
		}
	} else {
		sv, err = m.CreateService(svcName, exe, mgr.Config{DisplayName: svcDisplay, Description: svcDesc, StartType: mgr.StartAutomatic})
		if err != nil {
			return fmt.Errorf("create service: %w", err)
		}
	}
	defer sv.Close()
	_ = sv.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second}, {Type: mgr.ServiceRestart, Delay: 60 * time.Second}}, 86400)
	if err := sv.Start(); err != nil && !strings.Contains(err.Error(), "already running") {
		return fmt.Errorf("start: %w", err)
	}
	fmt.Printf("Installed and started %q as %s\nConfig: %s (SYSTEM and Administrators only)\nLogs:   %s\n", svcDisplay, exe, filepath.Join(dd, "agent.json"), filepath.Join(dd, "logs"))
	return nil
}

func uninstall(m *mgr.Mgr) error {
	s, err := m.OpenService(svcName)
	if err != nil {
		return fmt.Errorf("service not installed: %w", err)
	}
	_, _ = s.Control(svc.Stop)
	for i := 0; i < 20; i++ {
		if st, err := s.Query(); err != nil || st.State == svc.Stopped {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	err = s.Delete()
	s.Close()
	if err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(dataDir(), "agent.json")) // the protected enrollment token
	fmt.Println("Service removed. Logs are kept in", filepath.Join(dataDir(), "logs"))
	return nil
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst + ".new")
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(dst+".new", dst)
}

func openLog(name string) {
	dir := filepath.Join(dataDir(), "logs")
	_ = os.MkdirAll(dir, 0o700)
	p := filepath.Join(dir, name)
	if st, err := os.Stat(p); err == nil && st.Size() > 10<<20 { // keep one old log of 10 MB
		_ = os.Rename(p, p+".1")
	}
	if f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
		log.SetOutput(f)
	}
}

/* ---------------- the running service: helper supervisor ---------------- */

func runAsService() (bool, error) {
	is, err := svc.IsWindowsService()
	if err != nil || !is {
		return false, nil
	}
	openLog("service.log")
	return true, svc.Run(svcName, &service{})
}

type service struct{}

func (s *service) Execute(args []string, req <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	sup := newSupervisor()
	go sup.loop()
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	log.Printf("service %s %s started", svcName, version)
	for c := range req {
		switch c.Cmd {
		case svc.Interrogate:
			st <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			st <- svc.Status{State: svc.StopPending}
			sup.stop()
			log.Printf("service stopped")
			return false, 0
		}
	}
	return false, 0
}

type supervisor struct {
	mu      sync.Mutex
	quit    chan struct{}
	job     windows.Handle
	proc    windows.Handle
	session uint32
	fails   int
}

func newSupervisor() *supervisor {
	s := &supervisor{quit: make(chan struct{}), session: ^uint32(0)}
	// Helpers live in a job that is killed when the service process ends, even if it crashes.
	if j, err := windows.CreateJobObject(nil, nil); err == nil {
		info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
		info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
		if _, err := windows.SetInformationJobObject(j, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err == nil {
			s.job = j
		}
	}
	return s
}

func (s *supervisor) stop() {
	close(s.quit)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.killLocked()
}

func (s *supervisor) killLocked() {
	if s.proc != 0 {
		_ = windows.TerminateProcess(s.proc, 0)
		_ = windows.CloseHandle(s.proc)
		s.proc = 0
	}
}

func (s *supervisor) loop() {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		s.tick()
		select {
		case <-s.quit:
			return
		case <-t.C:
		}
	}
}

func (s *supervisor) tick() {
	want := pickSession()
	s.mu.Lock()
	defer s.mu.Unlock()
	alive := false
	if s.proc != 0 {
		if ev, _ := windows.WaitForSingleObject(s.proc, 0); ev == uint32(windows.WAIT_TIMEOUT) {
			alive = true
		} else {
			var code uint32
			_ = windows.GetExitCodeProcess(s.proc, &code)
			log.Printf("helper in session %d exited (code %d)", s.session, code)
			_ = windows.CloseHandle(s.proc)
			s.proc = 0
		}
	}
	if alive && want == s.session {
		s.fails = 0
		return
	}
	if want == ^uint32(0) {
		return // no session with a desktop yet (early boot)
	}
	if alive {
		log.Printf("active session changed %d -> %d; moving the helper", s.session, want)
		s.killLocked()
	}
	if s.fails > 3 { // back off a crashing helper: one try every ~30 s
		s.fails++
		if s.fails%15 != 0 {
			return
		}
	}
	proc, err := launchHelper(want, s.job)
	if err != nil {
		s.fails++
		log.Printf("launch helper in session %d: %v", want, err)
		return
	}
	s.proc, s.session = proc, want
	s.fails++
	log.Printf("helper started in session %d", want)
}

// pickSession prefers the session the user is actually looking at: the console session when
// it is active, else an active remote (RDP, Hyper-V Enhanced Session) session, else the console
// session (which then shows the logon screen).
func pickSession() uint32 {
	console := windows.WTSGetActiveConsoleSessionId()
	var infos *windows.WTS_SESSION_INFO
	var n uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &infos, &n); err != nil {
		return console
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(infos)))
	list := unsafe.Slice(infos, n)
	other := ^uint32(0)
	for _, si := range list {
		if si.SessionID == 0 || si.State != windows.WTSActive {
			continue
		}
		if si.SessionID == console {
			return console
		}
		if other == ^uint32(0) {
			other = si.SessionID
		}
	}
	if other != ^uint32(0) {
		return other
	}
	return console
}

// launchHelper starts "aegis-rc-agent.exe helper" in the given session as SYSTEM.
func launchHelper(session uint32, job windows.Handle) (windows.Handle, error) {
	var self windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY|
		windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_ADJUST_SESSIONID, &self); err != nil {
		return 0, fmt.Errorf("open token: %w", err)
	}
	defer self.Close()
	var tok windows.Token
	if err := windows.DuplicateTokenEx(self, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenPrimary, &tok); err != nil {
		return 0, fmt.Errorf("duplicate token: %w", err)
	}
	defer tok.Close()
	sid := session
	if err := windows.SetTokenInformation(tok, windows.TokenSessionId, (*byte)(unsafe.Pointer(&sid)), uint32(unsafe.Sizeof(sid))); err != nil {
		return 0, fmt.Errorf("set session: %w", err)
	}
	var env *uint16
	if err := windows.CreateEnvironmentBlock(&env, tok, false); err == nil {
		defer windows.DestroyEnvironmentBlock(env)
	}
	exe, err := os.Executable()
	if err != nil {
		return 0, err
	}
	cmd, _ := windows.UTF16PtrFromString(`"` + exe + `" helper`)
	desk, _ := windows.UTF16PtrFromString(`winsta0\default`)
	dir, _ := windows.UTF16PtrFromString(filepath.Dir(exe))
	si := windows.StartupInfo{Desktop: desk, Flags: windows.STARTF_USESHOWWINDOW, ShowWindow: windows.SW_HIDE}
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation
	if err := windows.CreateProcessAsUser(tok, nil, cmd, nil, nil, false,
		windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_NO_WINDOW|windows.CREATE_SUSPENDED, env, dir, &si, &pi); err != nil {
		return 0, fmt.Errorf("create process: %w", err)
	}
	if job != 0 {
		_ = windows.AssignProcessToJobObject(job, pi.Process)
	}
	_, _ = windows.ResumeThread(pi.Thread)
	_ = windows.CloseHandle(pi.Thread)
	return pi.Process, nil
}

/* ---------------- the helper ---------------- */

func runHelper() error {
	var sess uint32
	_ = windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &sess)
	openLog(fmt.Sprintf("helper-session%d.log", sess))
	s, err := loadConfig()
	if err != nil {
		log.Printf("config: %v", err)
		return err
	}
	return run(s, true)
}
