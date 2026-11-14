// Command aegis-rc-server runs the Aegis Remote Control signaling server (TLS 1.3 only).
//
//	aegis-rc-server -addr :8443 -data ./aegis-rc-data
//	aegis-rc-server -turn turns:turn.example.com:5349 -ice stun:turn.example.com:3478   (secret in AEGIS_TURN_SECRET)
//
// First run creates the TLS certificate, the open_rc signing key, operator tokens, the agent
// enrollment token and the default consent-first policy in the data folder.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"aegis-one/rc/internal/server"
)

func main() {
	addr := flag.String("addr", ":8443", "listen address")
	data := flag.String("data", "aegis-rc-data", "folder for keys, tokens, policy and the audit log")
	hosts := flag.String("hosts", "", "extra host names or IPs for the certificate, comma separated")
	ice := flag.String("ice", "", "STUN URLs handed to browsers and agents, comma separated (optional)")
	turn := flag.String("turn", "", "TURN URLs of a coturn server using use-auth-secret, comma separated (optional)")
	turnTTL := flag.Duration("turn-ttl", 2*time.Hour, "lifetime of the per-session TURN credentials")
	logFmt := flag.String("log-format", "text", "log format: text or json")
	flag.Parse()

	var h slog.Handler = slog.NewTextHandler(os.Stderr, nil)
	if *logFmt == "json" {
		h = slog.NewJSONHandler(os.Stderr, nil)
	}
	slog.SetDefault(slog.New(h))

	split := func(s string) []string {
		var out []string
		for _, p := range strings.Split(s, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	// The TURN shared secret comes from the environment, never a flag: flags are visible to every
	// user on the machine in the process list.
	secret := os.Getenv("AEGIS_TURN_SECRET")
	if *turn != "" && secret == "" {
		fmt.Fprintln(os.Stderr, "-turn needs the coturn static-auth-secret in the AEGIS_TURN_SECRET environment variable")
		os.Exit(2)
	}
	s, err := server.New(server.Config{Addr: *addr, DataDir: *data, Hosts: split(*hosts), ICEServers: split(*ice),
		TURNURLs: split(*turn), TURNSecret: secret, TURNTTL: *turnTTL})
	if err != nil {
		slog.Error("start failed", "err", err)
		os.Exit(1)
	}
	if err := s.ListenAndServe(); err != nil {
		slog.Error("server stopped", "err", err)
		os.Exit(1)
	}
}
