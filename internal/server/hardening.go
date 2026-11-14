package server

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"aegis-one/rc/internal/wire"
)

/* ---------------- TURN: short-lived credentials ---------------- */

// iceFor returns the ICE servers for one peer connection. STUN entries pass through as they are.
// TURN entries get credentials in the coturn "use-auth-secret" (TURN REST API) form:
//
//	username   = "<unix expiry>:<psid>"
//	credential = base64(HMAC-SHA1(shared secret, username))
//
// coturn checks them with the same shared secret, so no per-user TURN accounts exist and a
// leaked credential stops working after TURNTTL.
func (s *Server) iceFor(psid string, now time.Time) []wire.ICEServer {
	var out []wire.ICEServer
	for _, u := range s.cfg.ICEServers {
		out = append(out, wire.ICEServer{URLs: []string{u}})
	}
	if len(s.cfg.TURNURLs) == 0 || s.cfg.TURNSecret == "" {
		return out
	}
	ttl := s.cfg.TURNTTL
	if ttl <= 0 {
		ttl = 2 * time.Hour
	}
	user := fmt.Sprintf("%d:%s", now.Add(ttl).Unix(), psid)
	return append(out, wire.ICEServer{URLs: s.cfg.TURNURLs, Username: user, Credential: TURNCredential(s.cfg.TURNSecret, user)})
}

// TURNCredential is the coturn REST API password for a username.
func TURNCredential(secret, user string) string {
	m := hmac.New(sha1.New, []byte(secret))
	m.Write([]byte(user))
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

/* ---------------- rate limiting ---------------- */

// limiter blocks a client address after too many failed logins, and caps how fast one console
// may ask for sessions. It is in memory: enough for one server instance (see Scale/HA notes).
type limiter struct {
	mu    sync.Mutex
	fails map[string]*failWindow
	hits  map[string][]time.Time
}

type failWindow struct {
	n     int
	first time.Time
	until time.Time
}

const (
	maxFails    = 5
	failWindowD = 5 * time.Minute
	blockFor    = 10 * time.Minute
)

func newLimiter() *limiter {
	return &limiter{fails: map[string]*failWindow{}, hits: map[string][]time.Time{}}
}

// blocked reports whether ip is locked out, and until when.
func (l *limiter) blocked(ip string, now time.Time) (bool, time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.fails[ip]
	if f == nil || now.After(f.until) {
		return false, time.Time{}
	}
	return true, f.until
}

// fail records a failed login; the fifth failure inside five minutes blocks the address.
func (l *limiter) fail(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.fails[ip]
	if f == nil || now.Sub(f.first) > failWindowD {
		f = &failWindow{first: now}
		l.fails[ip] = f
	}
	f.n++
	if f.n >= maxFails {
		f.until = now.Add(blockFor)
		return true
	}
	return false
}

func (l *limiter) success(ip string) {
	l.mu.Lock()
	delete(l.fails, ip)
	l.mu.Unlock()
}

// allow is a sliding-window rate limit: at most n events per window for key.
func (l *limiter) allow(key string, n int, window time.Duration, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	keep := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if now.Sub(t) < window {
			keep = append(keep, t)
		}
	}
	if len(keep) >= n {
		l.hits[key] = keep
		return false
	}
	l.hits[key] = append(keep, now)
	return true
}

// sweep drops old entries so the maps do not grow without bound.
func (l *limiter) sweep(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, f := range l.fails {
		if now.Sub(f.first) > failWindowD && now.After(f.until) {
			delete(l.fails, k)
		}
	}
	for k, h := range l.hits {
		if len(h) == 0 || now.Sub(h[len(h)-1]) > time.Hour {
			delete(l.hits, k)
		}
	}
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return strings.TrimPrefix(h, "::ffff:")
}

/* ---------------- WebSocket keepalive ---------------- */

const (
	pingEvery = 25 * time.Second
	pongWait  = 70 * time.Second
)

// keepalive pings the peer and drops the connection when pongs stop, so a dead agent or console
// is noticed within about a minute instead of on the next write. Browsers and gorilla clients
// answer pings automatically.
func keepalive(c *conn, done <-chan struct{}) {
	ws := c.ws
	_ = ws.SetReadDeadline(time.Now().Add(pongWait))
	ws.SetPongHandler(func(string) error { return ws.SetReadDeadline(time.Now().Add(pongWait)) })
	t := time.NewTicker(pingEvery)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			c.mu.Lock()
			err := ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second))
			c.mu.Unlock()
			if err != nil {
				_ = ws.Close()
				return
			}
		}
	}
}
