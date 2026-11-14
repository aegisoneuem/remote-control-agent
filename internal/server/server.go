// Package server is the Aegis Remote Control signaling server (prototype of the
// internal/remotecontrol module proposed for aegis_one_server).
//
// It never sees screen data: it authenticates operators and agents, checks permissions before
// the end user is asked (RBAC before consent), signs open_rc with Ed25519, relays SDP/ICE, keeps
// the session policy, and writes an audit log of metadata only.
package server

import (
	"bufio"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"aegis-one/rc/internal/rec"
	"aegis-one/rc/internal/store"
	"aegis-one/rc/internal/wire"
)

const Version = "0.3.0"

// Permissions, mirroring the remotecontrol.* consts proposed for apiauth.
const (
	PermStart     = "remotecontrol.start"
	PermControl   = "remotecontrol.control"
	PermRecording = "remotecontrol.recording.view"
	PermPolicy    = "remotecontrol.policy"
	PermAudit     = "remotecontrol.audit"
)

type Operator struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	TokenHash string   `json:"token_sha256"`
	Perms     []string `json:"perms"`
}

type Config struct {
	Addr       string
	DataDir    string
	Hosts      []string
	ICEServers []string      // STUN URLs handed out as they are
	TURNURLs   []string      // turn:/turns: URLs of a coturn server using use-auth-secret
	TURNSecret string        // coturn static-auth-secret; credentials are minted per session
	TURNTTL    time.Duration // lifetime of minted TURN credentials (default 2h)
}

type Server struct {
	cfg       Config
	priv      ed25519.PrivateKey
	keyID     string
	certFP    string
	enrollH   string
	mu        sync.Mutex
	operators []Operator
	policy    wire.Policy
	agents    map[string]*agentConn // by device name (lower case)
	consoles  map[*consoleConn]bool
	routes    map[string]*route // psid -> who is on each end
	auditMu   sync.Mutex
	auditF    *os.File // append-only JSON lines export of the audit log (for a SIEM)
	db        *store.Store
	recKey    *ecdh.PrivateKey
	recKeyID  string
	recPub    string
	issued    map[string]issuedSession // session id -> what this server signed it for
	upgrader  websocket.Upgrader
	lim       *limiter
}

type issuedSession struct {
	device, operator, reason string
	at                       time.Time
}

type agentConn struct {
	c      *conn
	info   wire.AgentInfo
	remote string
}

type consoleConn struct {
	c  *conn
	op *Operator
}

type route struct {
	console *consoleConn
	agent   *agentConn
	session string
	device  string
	op      string
}

type conn struct {
	mu sync.Mutex
	ws *websocket.Conn
}

func (c *conn) send(m wire.Msg) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return c.ws.WriteJSON(m)
}

func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func hashToken(t string) string { s := sha256.Sum256([]byte(t)); return hex.EncodeToString(s[:]) }

// New loads or creates the server's certificate, signing key, operators and policy.
func New(cfg Config) (*Server, error) {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, agents: map[string]*agentConn{}, consoles: map[*consoleConn]bool{}, routes: map[string]*route{}, lim: newLimiter(), issued: map[string]issuedSession{}}
	s.upgrader = websocket.Upgrader{ReadBufferSize: 64 << 10, WriteBufferSize: 64 << 10,
		// Tokens travel in the first message, never in cookies, so a hostile page cannot ride an
		// operator's browser session. The console may also be opened from a file (Origin "null").
		CheckOrigin: func(r *http.Request) bool { return true }}
	db, err := store.Open(filepath.Join(cfg.DataDir, "aegis-rc.db"))
	if err != nil {
		return nil, fmt.Errorf("database: %w", err)
	}
	s.db = db
	if s.recKey, err = rec.LoadOrCreateKey(filepath.Join(cfg.DataDir, "recording.key")); err != nil {
		return nil, err
	}
	rp := s.recKey.PublicKey().Bytes()
	s.recKeyID, s.recPub = rec.KeyID(rp), base64.StdEncoding.EncodeToString(rp)
	if err := os.MkdirAll(filepath.Join(cfg.DataDir, "recordings"), 0o700); err != nil {
		return nil, err
	}
	var secrets []string
	if err := s.loadKey(&secrets); err != nil {
		return nil, err
	}
	if err := s.loadOperators(&secrets); err != nil {
		return nil, err
	}
	if err := s.loadPolicy(); err != nil {
		return nil, err
	}
	if len(secrets) > 0 {
		p := filepath.Join(cfg.DataDir, "FIRST-RUN-SECRETS.txt")
		body := "Aegis RC first-run secrets. Copy them somewhere safe, then delete this file.\n\n" + strings.Join(secrets, "\n") + "\n"
		_ = os.WriteFile(p, []byte(body), 0o600)
		// printed once to the console window, never to the structured log
		fmt.Fprintf(os.Stderr, "first run: secrets written to %s (shown once below)\n\n%s\n\n", p, strings.Join(secrets, "\n"))
	}
	s.migrateAudit()
	f, err := os.OpenFile(filepath.Join(cfg.DataDir, "audit.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	s.auditF = f
	return s, nil
}

func (s *Server) loadKey(secrets *[]string) error {
	kp := filepath.Join(s.cfg.DataDir, "signing.key")
	b, err := os.ReadFile(kp)
	if errors.Is(err, os.ErrNotExist) {
		_, priv, gerr := ed25519.GenerateKey(rand.Reader)
		if gerr != nil {
			return gerr
		}
		if err := os.WriteFile(kp, []byte(base64.StdEncoding.EncodeToString(priv.Seed())), 0o600); err != nil {
			return err
		}
		b, _ = os.ReadFile(kp)
	} else if err != nil {
		return err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return errors.New("signing.key is corrupt")
	}
	s.priv = ed25519.NewKeyFromSeed(seed)
	pub := s.priv.Public().(ed25519.PublicKey)
	s.keyID = wire.KeyID(pub)
	// agents are provisioned with this file (key id + public key); never the private key
	trust := fmt.Sprintf("%s %s\n", s.keyID, base64.StdEncoding.EncodeToString(pub))
	_ = os.WriteFile(filepath.Join(s.cfg.DataDir, "agent-trust.pub"), []byte(trust), 0o644)

	ep := filepath.Join(s.cfg.DataDir, "enroll.sha256")
	if eb, err := os.ReadFile(ep); err == nil {
		s.enrollH = strings.TrimSpace(string(eb))
	} else {
		t := randToken(24)
		s.enrollH = hashToken(t)
		_ = os.WriteFile(ep, []byte(s.enrollH), 0o600)
		*secrets = append(*secrets, "Agent enrollment token: "+t)
	}
	return nil
}

func (s *Server) loadOperators(secrets *[]string) error {
	ops, err := s.db.Operators()
	if err != nil {
		return err
	}
	if len(ops) == 0 {
		// one-time migration from the 0.1/0.2 JSON file, else seed the three test operators
		if b, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "operators.json")); err == nil {
			var old []Operator
			if json.Unmarshal(b, &old) == nil {
				for _, o := range old {
					_ = s.db.PutOperator(store.Operator{ID: o.ID, Name: o.Name, TokenHash: o.TokenHash, Perms: o.Perms})
				}
				slog.Info("migrated operators.json into the database", "operators", len(old))
			}
		} else {
			all := []string{PermStart, PermControl, PermRecording, PermPolicy, PermAudit}
			seed := []struct {
				id, name string
				perms    []string
			}{{"op-admin", "Aegis Admin", all}, {"op-karan", "Karan", []string{PermStart, PermControl}}, {"op-priya", "Priya N.", []string{PermStart}}}
			for _, o := range seed {
				t := randToken(18)
				if err := s.db.PutOperator(store.Operator{ID: o.id, Name: o.name, TokenHash: hashToken(t), Perms: o.perms}); err != nil {
					return err
				}
				*secrets = append(*secrets, fmt.Sprintf("Operator token for %s (%s): %s", o.name, strings.Join(o.perms, ", "), t))
			}
		}
		if ops, err = s.db.Operators(); err != nil {
			return err
		}
	}
	s.operators = s.operators[:0]
	for _, o := range ops {
		if !o.Disabled {
			s.operators = append(s.operators, Operator{ID: o.ID, Name: o.Name, TokenHash: o.TokenHash, Perms: o.Perms})
		}
	}
	return nil
}

func (s *Server) loadPolicy() error {
	s.policy = wire.DefaultPolicy()
	found, err := s.db.Get("policy", &s.policy)
	if err != nil {
		return err
	}
	if !found {
		if b, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "policy.json")); err == nil {
			_ = json.Unmarshal(b, &s.policy)
		}
		return s.savePolicy()
	}
	if s.policy.RetentionDays <= 0 { // policies saved before retention existed
		s.policy.RetentionDays = 30
	}
	return nil
}

func (s *Server) savePolicy() error {
	return s.db.Put("policy", s.policy)
}

func (s *Server) audit(e wire.AuditEntry) {
	e.At = time.Now().UTC().Format(time.RFC3339)
	if err := s.db.AddAudit(store.Audit{At: e.At, Event: e.Event, Operator: e.Operator, Device: e.Device, Session: e.Session, Detail: e.Detail}); err != nil {
		slog.Error("audit write failed", "err", err, "event", e.Event)
	}
	b, _ := json.Marshal(e)
	s.auditMu.Lock()
	if s.auditF != nil {
		_, _ = s.auditF.Write(append(b, '\n'))
	}
	s.auditMu.Unlock()
	slog.Info("audit", "event", e.Event, "operator", e.Operator, "device", e.Device, "session", e.Session, "detail", e.Detail)
}

// migrateAudit copies an existing audit.jsonl into an empty database once.
func (s *Server) migrateAudit() {
	if n, err := s.db.AuditCount(); err != nil || n > 0 {
		return
	}
	f, err := os.Open(filepath.Join(s.cfg.DataDir, "audit.jsonl"))
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	n := 0
	for sc.Scan() {
		var e wire.AuditEntry
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			_ = s.db.AddAudit(store.Audit{At: e.At, Event: e.Event, Operator: e.Operator, Device: e.Device, Session: e.Session, Detail: e.Detail})
			n++
		}
	}
	if n > 0 {
		slog.Info("migrated audit.jsonl into the database", "entries", n)
	}
}

func (s *Server) readAudit(n int) []wire.AuditEntry {
	rows, err := s.db.RecentAudit(n)
	if err != nil {
		slog.Error("audit read failed", "err", err)
		return nil
	}
	out := make([]wire.AuditEntry, 0, len(rows))
	for _, e := range rows {
		out = append(out, wire.AuditEntry{At: e.At, Event: e.Event, Operator: e.Operator, Device: e.Device, Session: e.Session, Detail: e.Detail})
	}
	return out
}

/* ---------------- TLS 1.3 ---------------- */

func (s *Server) tlsConfig() (*tls.Config, error) {
	cp, kp := filepath.Join(s.cfg.DataDir, "tls-cert.pem"), filepath.Join(s.cfg.DataDir, "tls-key.pem")
	if _, err := os.Stat(cp); errors.Is(err, os.ErrNotExist) {
		if err := s.makeCert(cp, kp); err != nil {
			return nil, err
		}
	}
	cert, err := tls.LoadX509KeyPair(cp, kp)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(cert.Certificate[0])
	s.certFP = hex.EncodeToString(sum[:])
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}, nil
}

func (s *Server) makeCert(cp, kp string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "Aegis RC server " + host, Organization: []string{"Aegis One (prototype)"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost", host}}
	tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && ipn.IP.To4() != nil {
				tmpl.IPAddresses = append(tmpl.IPAddresses, ipn.IP)
			}
		}
	}
	for _, h := range s.cfg.Hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	if err := os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return err
	}
	return os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
}

// ListenAndServe serves HTTPS and the two WebSocket endpoints, TLS 1.3 only.
func (s *Server) ListenAndServe() error {
	tc, err := s.tlsConfig()
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ws/agent", s.serveAgent)
	mux.HandleFunc("/ws/console", s.serveConsole)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "tls": "TLS 1.3", "key_id": s.keyID, "version": Version})
	})
	// Opening this page once lets a browser accept the server's own certificate before the
	// console (opened from its file) connects over WSS.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<!doctype html><title>Aegis RC server</title><body style=\"font:15px system-ui;padding:40px\"><h2>Aegis RC server is running</h2><p>This browser now trusts the server certificate. Go back to the Aegis console and choose Connect Server.</p><p>TLS 1.3 · signing key %s</p></body>", s.keyID)
	})
	hs := &http.Server{Addr: s.cfg.Addr, Handler: securityHeaders(mux), TLSConfig: tc, ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout: 120 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() { // keep the rate limiter's memory bounded
		s.sweepRecordings(time.Now())
		for range time.Tick(5 * time.Minute) {
			s.lim.sweep(time.Now())
			s.sweepRecordings(time.Now())
			s.mu.Lock()
			for id, is := range s.issued { // sessions are at most 12 h long
				if time.Since(is.at) > 24*time.Hour {
					delete(s.issued, id)
				}
			}
			s.mu.Unlock()
		}
	}()
	turn := "off"
	if len(s.cfg.TURNURLs) > 0 && s.cfg.TURNSecret != "" {
		turn = strings.Join(s.cfg.TURNURLs, ",")
	}
	slog.Info("Aegis RC server listening", "version", Version, "addr", s.cfg.Addr, "tls", "1.3 only", "turn", turn)
	slog.Info("open_rc signing key", "key_id", s.keyID, "agent_trust_file", filepath.Join(s.cfg.DataDir, "agent-trust.pub"))
	// also plain text, so it is easy to copy into the agent's start script
	fmt.Fprintf(os.Stderr, "certificate sha256 (agents pin this): %s\n", s.certFP)
	return hs.ListenAndServeTLS("", "")
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		h.ServeHTTP(w, r)
	})
}

func tokenEq(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

/* ---------------- agents ---------------- */

func (s *Server) serveAgent(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if b, until := s.lim.blocked(ip, time.Now()); b {
		http.Error(w, "too many failed attempts; try again after "+until.UTC().Format(time.RFC3339), http.StatusTooManyRequests)
		return
	}
	ws, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()
	ws.SetReadLimit(1 << 20)
	c := &conn{ws: ws}
	_ = ws.SetReadDeadline(time.Now().Add(15 * time.Second))
	var hello wire.Msg
	if err := ws.ReadJSON(&hello); err != nil || hello.T != "agent_auth" {
		return
	}
	if !tokenEq(hashToken(hello.Token), s.enrollH) || strings.TrimSpace(hello.Device) == "" {
		_ = c.send(wire.Msg{T: "error", Text: "enrollment token rejected"})
		s.audit(wire.AuditEntry{Event: "agent_rejected", Device: hello.Device, Detail: r.RemoteAddr})
		if s.lim.fail(ip, time.Now()) {
			s.audit(wire.AuditEntry{Event: "address_blocked", Detail: ip + " after repeated failed agent enrollments"})
		}
		return
	}
	s.lim.success(ip)
	done := make(chan struct{})
	defer close(done)
	go keepalive(c, done)
	ac := &agentConn{c: c, remote: r.RemoteAddr, info: wire.AgentInfo{Device: hello.Device, OS: hello.OS, User: hello.User, IP: hello.IP,
		Version: hello.Version, Caps: hello.Caps, Online: true, Screen: hello.Screen}}
	key := strings.ToLower(hello.Device)
	s.mu.Lock()
	if old := s.agents[key]; old != nil {
		_ = old.c.ws.Close()
	}
	s.agents[key] = ac
	s.mu.Unlock()
	_ = c.send(wire.Msg{T: "auth_ok", KeyID: s.keyID})
	s.audit(wire.AuditEntry{Event: "agent_online", Device: hello.Device, Detail: hello.OS + " · " + r.RemoteAddr})
	s.broadcastAgents()
	defer func() {
		s.mu.Lock()
		if s.agents[key] == ac {
			delete(s.agents, key)
		}
		for id, rt := range s.routes {
			if rt.agent == ac {
				delete(s.routes, id)
			}
		}
		s.mu.Unlock()
		s.audit(wire.AuditEntry{Event: "agent_offline", Device: hello.Device})
		s.broadcastAgents()
	}()
	for {
		var m wire.Msg
		if err := ws.ReadJSON(&m); err != nil {
			return
		}
		switch m.T {
		case "agent_state":
			s.mu.Lock()
			ac.info.User, ac.info.Session = m.User, m.Session2
			s.mu.Unlock()
			s.broadcastAgents()
		case "rc_status", "rc_deny", "rc_offer", "rc_ice":
			s.mu.Lock()
			rt := s.routes[m.PSID]
			if rt != nil && rt.agent != ac {
				rt = nil // an agent may only talk about its own sessions
			}
			s.mu.Unlock()
			if rt == nil {
				continue
			}
			if m.T == "rc_deny" {
				s.audit(wire.AuditEntry{Event: "rc_denied", Operator: rt.op, Device: rt.device, Session: rt.session, Detail: m.Reason})
			}
			_ = rt.console.c.send(m)
		case "rec_open", "rec_chunk", "rec_close":
			s.onRecording(ac, m)
		case "rc_event":
			op, _ := m.Extra["operator"].(string)
			s.audit(wire.AuditEntry{Event: m.K, Operator: op, Device: hello.Device, Session: m.Session, Detail: m.Text})
		}
	}
}

func (s *Server) agentList() []wire.AgentInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]wire.AgentInfo, 0, len(s.agents))
	for _, a := range s.agents {
		out = append(out, a.info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Device < out[j].Device })
	return out
}

func (s *Server) broadcastAgents() {
	list := s.agentList()
	s.mu.Lock()
	cs := make([]*consoleConn, 0, len(s.consoles))
	for c := range s.consoles {
		cs = append(cs, c)
	}
	s.mu.Unlock()
	for _, c := range cs {
		_ = c.c.send(wire.Msg{T: "agents", Agents: list})
	}
}

/* ---------------- consoles ---------------- */

func has(perms []string, p string) bool {
	for _, x := range perms {
		if x == p {
			return true
		}
	}
	return false
}

func (s *Server) serveConsole(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if b, until := s.lim.blocked(ip, time.Now()); b {
		http.Error(w, "too many failed attempts; try again after "+until.UTC().Format(time.RFC3339), http.StatusTooManyRequests)
		return
	}
	ws, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()
	ws.SetReadLimit(1 << 20)
	c := &conn{ws: ws}
	_ = ws.SetReadDeadline(time.Now().Add(30 * time.Second))
	var auth wire.Msg
	if err := ws.ReadJSON(&auth); err != nil || auth.T != "auth" {
		return
	}
	var op *Operator
	h := hashToken(auth.Token)
	s.mu.Lock()
	for i := range s.operators {
		if tokenEq(s.operators[i].TokenHash, h) {
			op = &s.operators[i]
		}
	}
	s.mu.Unlock()
	if op == nil {
		blocked := s.lim.fail(ip, time.Now())
		text := "Operator token not recognised."
		if blocked {
			text = "Operator token not recognised. Too many failed attempts: this address is blocked for 10 minutes."
			s.audit(wire.AuditEntry{Event: "address_blocked", Detail: ip + " after repeated failed console logins"})
		}
		_ = c.send(wire.Msg{T: "auth_failed", Text: text})
		s.audit(wire.AuditEntry{Event: "console_auth_failed", Detail: r.RemoteAddr})
		return
	}
	s.lim.success(ip)
	done := make(chan struct{})
	defer close(done)
	go keepalive(c, done)
	cc := &consoleConn{c: c, op: op}
	s.mu.Lock()
	s.consoles[cc] = true
	pol := s.policy
	s.mu.Unlock()
	s.audit(wire.AuditEntry{Event: "console_connected", Operator: op.Name, Detail: r.RemoteAddr})
	_ = c.send(wire.Msg{T: "hello", Operator: &wire.OperatorInfo{ID: op.ID, Name: op.Name, Perms: op.Perms},
		Server: &wire.ServerInfo{Version: Version, TLS: "TLS 1.3", KeyID: s.keyID, ICEServers: s.cfg.ICEServers}, Policy: &pol, Agents: s.agentList()})
	defer func() {
		s.mu.Lock()
		delete(s.consoles, cc)
		var gone []*route
		for id, rt := range s.routes {
			if rt.console == cc {
				gone = append(gone, rt)
				delete(s.routes, id)
				_ = rt.agent.c.send(wire.Msg{T: "rc_close", PSID: id, End: true, Close: wire.CloseConsoleGone})
			}
		}
		s.mu.Unlock()
		_ = gone
	}()
	for {
		var m wire.Msg
		if err := ws.ReadJSON(&m); err != nil {
			return
		}
		switch m.T {
		case "rc_start":
			if !s.lim.allow("start:"+op.ID, 20, time.Minute, time.Now()) {
				_ = c.send(wire.Msg{T: "rc_deny", PSID: m.PSID, Close: wire.CloseRateLimited, Reason: "Too many session requests. Wait a minute and try again."})
				continue
			}
			s.start(cc, m)
		case "rc_answer", "rc_ice", "rc_close":
			s.mu.Lock()
			rt := s.routes[m.PSID]
			if rt != nil && rt.console != cc {
				rt = nil // a console may only signal its own sessions
			}
			if rt != nil && m.T == "rc_close" {
				delete(s.routes, m.PSID)
			}
			s.mu.Unlock()
			if rt == nil {
				continue
			}
			if m.T == "rc_close" {
				s.audit(wire.AuditEntry{Event: "rc_close", Operator: op.Name, Device: rt.device, Session: rt.session, Detail: map[bool]string{true: "ended by controller", false: "left"}[m.End]})
			}
			cl := ""
			if m.T == "rc_close" && m.End {
				cl = wire.CloseOperatorEnded
			}
			_ = rt.agent.c.send(wire.Msg{T: m.T, PSID: m.PSID, SDP: m.SDP, C: m.C, End: m.End, Close: cl})
		case "policy_set":
			if !has(op.Perms, PermPolicy) || m.Policy == nil {
				_ = c.send(wire.Msg{T: "error", Text: "You do not have permission to change the remote control policy."})
				continue
			}
			p := *m.Policy
			if p.Consent != "unattended_if_no_user" {
				p.Consent = "always"
			}
			p.IdleSec, p.MaxSec = clampInt(p.IdleSec, 60, 14400), clampInt(p.MaxSec, 300, 43200)
			p.RetentionDays = clampInt(p.RetentionDays, 1, 3650)
			s.mu.Lock()
			s.policy = p
			err := s.savePolicy()
			s.mu.Unlock()
			b, _ := json.Marshal(p)
			s.audit(wire.AuditEntry{Event: "policy_changed", Operator: op.Name, Detail: string(b)})
			if err == nil {
				s.broadcastPolicy()
			}
		case "audit_list":
			if !has(op.Perms, PermAudit) {
				_ = c.send(wire.Msg{T: "error", Text: "You do not have permission to read the audit log."})
				continue
			}
			_ = c.send(wire.Msg{T: "audit", Audit: s.readAudit(300)})
		case "rec_list", "rec_get":
			if !has(op.Perms, PermRecording) {
				_ = c.send(wire.Msg{T: "error", Text: "You do not have permission to view recordings (remotecontrol.recording.view)."})
				continue
			}
			if m.T == "rec_list" {
				_ = c.send(wire.Msg{T: "recordings", Recs: s.recList()})
			} else {
				go s.playRecording(cc, m.Session)
			}
		}
	}
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func (s *Server) broadcastPolicy() {
	s.mu.Lock()
	p := s.policy
	cs := make([]*consoleConn, 0, len(s.consoles))
	for c := range s.consoles {
		cs = append(cs, c)
	}
	s.mu.Unlock()
	for _, c := range cs {
		_ = c.c.send(wire.Msg{T: "policy", Policy: &p})
	}
}

// start checks permissions first (RBAC before consent), then signs and sends open_rc.
func (s *Server) start(cc *consoleConn, m wire.Msg) {
	op := cc.op
	fail := func(code, reason string) {
		s.audit(wire.AuditEntry{Event: "rc_refused", Operator: op.Name, Device: m.Device, Detail: code + ": " + reason})
		_ = cc.c.send(wire.Msg{T: "rc_deny", PSID: m.PSID, Close: code, Reason: reason})
	}
	mode := m.Mode
	if mode != "control" && mode != "chat" {
		mode = "view"
	}
	role := "controller"
	if m.Join != "" {
		role, mode = "viewer", "view"
	}
	if !has(op.Perms, PermStart) {
		fail(wire.ClosePermissionDenied, "You do not have permission to start remote sessions (remotecontrol.start).")
		return
	}
	if mode == "control" && !has(op.Perms, PermControl) {
		fail(wire.ClosePermissionDenied, "You do not have permission to take control (remotecontrol.control). Start a View Only session instead.")
		return
	}
	s.mu.Lock()
	ac := s.agents[strings.ToLower(m.Device)]
	pol := s.policy
	s.mu.Unlock()
	if ac == nil {
		fail(wire.CloseAgentOffline, "No Aegis agent is connected for "+m.Device+".")
		return
	}
	reason := strings.TrimSpace(m.Reason)
	if len(reason) > 200 {
		reason = reason[:200]
	}
	if role == "controller" && reason == "" {
		fail(wire.CloseReasonRequired, "A reason or ticket number is required.")
		return
	}
	session := m.Join
	if session == "" && role == "controller" {
		session = m.Session // reopening an existing session; the agent only allows its own controller
	}
	if session == "" {
		session = "RC-" + strings.ToUpper(randHex(3))
	}
	psid := "S" + strings.ToUpper(randHex(5))
	ice := s.iceFor(psid, time.Now())
	cmd := wire.OpenRC{ICE: ice, RecKeyID: s.recKeyID, RecPub: s.recPub, Type: "open_rc", SID: psid, Session: session, Device: ac.info.Device, Operator: op.Name, OperatorID: op.ID,
		Role: role, Mode: mode, Reason: reason, Policy: pol, Issued: time.Now().UnixMilli(), TTL: 60, Nonce: randToken(9), KeyID: s.keyID}
	b64, sig, err := wire.Sign(s.priv, cmd)
	if err != nil {
		fail(wire.CloseInternal, "Could not sign the request.")
		return
	}
	s.mu.Lock()
	if role == "controller" {
		if _, ok := s.issued[session]; !ok {
			s.issued[session] = issuedSession{device: ac.info.Device, operator: op.Name, reason: reason, at: time.Now()}
		}
	}
	s.routes[psid] = &route{console: cc, agent: ac, session: session, device: ac.info.Device, op: op.Name}
	s.mu.Unlock()
	s.audit(wire.AuditEntry{Event: "rc_requested", Operator: op.Name, Device: ac.info.Device, Session: session,
		Detail: fmt.Sprintf("%s %s · reason: %s · signed with %s", role, mode, reason, s.keyID)})
	_ = cc.c.send(wire.Msg{T: "rc_started", PSID: psid, Session: session, Device: ac.info.Device, KeyID: s.keyID, Code: wire.VerifyCode(psid), Mode: mode, ICE: ice})
	_ = ac.c.send(wire.Msg{T: "open_rc", PSID: psid, CmdB64: b64, Sig: sig, KeyID: s.keyID})
}
