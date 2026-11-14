// Command aegis-rc-agent is the Aegis Remote Control endpoint agent.
//
// Foreground (testing, runs in the signed-in user's session):
//
//	aegis-rc-agent -server wss://SERVER:8443 -token ENROLL_TOKEN -trust agent-trust.pub -pin CERT_SHA256
//
// Windows service (production: survives reboot and logoff, handles UAC, the lock screen and
// Ctrl+Alt+Del; run from an elevated prompt):
//
//	aegis-rc-agent service install -server wss://SERVER:8443 -token ENROLL_TOKEN -trust agent-trust.pub -pin CERT_SHA256
//	aegis-rc-agent service status | start | stop | uninstall
//
// It connects outbound only, so no inbound port is opened on the endpoint, and asks the
// signed-in user before every session.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"aegis-one/rc/internal/agent"
	"aegis-one/rc/internal/platform"
)

const version = "0.3.0"

// settings is what the agent needs to run; the service stores it in its protected config file.
type settings struct {
	Server      string   `json:"server"`
	Token       string   `json:"-"` // never written in clear; see the service config
	Trust       string   `json:"-"` // file contents, not a path, once installed
	Pin         string   `json:"pin"`
	Insecure    bool     `json:"insecure,omitempty"`
	Device      string   `json:"device"`
	AllowReboot bool     `json:"allow_reboot,omitempty"`
	ICE         []string `json:"ice,omitempty"`
	FPS         int      `json:"fps"`
	Video       bool     `json:"video"`
	FFmpeg      string   `json:"ffmpeg,omitempty"`
	Capture     string   `json:"capture,omitempty"`
}

func parseFlags(fs *flag.FlagSet, args []string) (settings, string, error) {
	var s settings
	fs.StringVar(&s.Server, "server", "", "server URL, e.g. wss://192.168.1.10:8443")
	fs.StringVar(&s.Token, "token", "", "agent enrollment token from the server's first run")
	trust := fs.String("trust", "agent-trust.pub", "file with the server's open_rc signing key (key id and public key)")
	fs.StringVar(&s.Pin, "pin", "", "server certificate SHA-256 fingerprint to pin")
	fs.BoolVar(&s.Insecure, "insecure", false, "accept the server certificate without a pin (testing only)")
	fs.StringVar(&s.Device, "device", "", "device name shown in the console (default: computer name)")
	fs.BoolVar(&s.AllowReboot, "allow-reboot", false, "allow operators to restart this computer (the user still has to approve)")
	ice := fs.String("ice", "", "extra STUN URLs, comma separated (the server also sends per-session STUN/TURN)")
	fs.IntVar(&s.FPS, "fps", 12, "maximum screen frames per second for JPEG tiles")
	fs.BoolVar(&s.Video, "video", true, "send H.264 video when FFmpeg is available (JPEG tiles otherwise)")
	fs.StringVar(&s.FFmpeg, "ffmpeg", "", "path to ffmpeg(.exe); default: next to the agent or on PATH")
	fs.StringVar(&s.Capture, "capture", "gdi", "Windows screen capture: gdi, or dxgi (Desktop Duplication, falls back to gdi)")
	if err := fs.Parse(args); err != nil {
		return s, "", err
	}
	for _, u := range strings.Split(*ice, ",") {
		if u = strings.TrimSpace(u); u != "" {
			s.ICE = append(s.ICE, u)
		}
	}
	if s.Device == "" {
		s.Device, _ = os.Hostname()
	}
	if s.Server == "" || s.Token == "" {
		return s, "", fmt.Errorf("-server and -token are required")
	}
	b, err := os.ReadFile(*trust)
	if err != nil {
		return s, "", fmt.Errorf("trusted key file: %w", err)
	}
	s.Trust = string(b)
	return s, *trust, nil
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "service":
			if err := serviceCommand(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "service:", err)
				os.Exit(1)
			}
			return
		case "helper":
			if err := runHelper(); err != nil {
				log.Fatalf("helper: %v", err)
			}
			return
		}
	}
	if handled, err := runAsService(); handled {
		if err != nil {
			log.Fatalf("service: %v", err)
		}
		return
	}
	s, _, err := parseFlags(flag.CommandLine, os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, "usage: aegis-rc-agent -server wss://HOST:8443 -token TOKEN -trust agent-trust.pub -pin CERT_SHA256")
		fmt.Fprintln(os.Stderr, "       aegis-rc-agent service install|uninstall|start|stop|status ...")
		os.Exit(2)
	}
	if err := run(s, false); err != nil {
		log.Fatal(err)
	}
}

// run starts the agent with a platform for this session. serviceMode means the process is the
// SYSTEM helper the service launched into the user's session.
func run(s settings, serviceMode bool) error {
	keys, err := parseTrust(s.Trust)
	if err != nil {
		return fmt.Errorf("trusted key: %w", err)
	}
	platform.CaptureMode = s.Capture
	p, err := platform.New()
	if err != nil {
		return fmt.Errorf("platform: %w", err)
	}
	mode := "foreground"
	if serviceMode {
		mode = "service helper (SYSTEM, user session)"
	}
	log.Printf("Aegis RC agent %s on %s (%s, %s) · %d trusted signing key(s)", version, s.Device, p.Name(), mode, len(keys))
	agent.New(agent.Config{Server: s.Server, EnrollToken: s.Token, Device: s.Device, TrustedKeys: keys, CertSHA256: s.Pin, Insecure: s.Insecure,
		AllowReboot: s.AllowReboot, ICEServers: s.ICE, Version: version, FPS: s.FPS, ServiceMode: serviceMode,
		Video: s.Video, FFmpeg: s.FFmpeg}, p).Run()
	return nil
}

// parseTrust reads "KEYID BASE64PUBKEY" lines; several lines allow key rotation.
func parseTrust(text string) (map[string]ed25519.PublicKey, error) {
	out := map[string]ed25519.PublicKey{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) != 2 || strings.HasPrefix(f[0], "#") {
			continue
		}
		k, err := base64.StdEncoding.DecodeString(f[1])
		if err != nil || len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("bad key on line %q", line)
		}
		out[f[0]] = ed25519.PublicKey(k)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no keys in the trust file")
	}
	return out, nil
}
