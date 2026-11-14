package server

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"testing"
	"time"
)

func TestTURNCredentialMatchesCoturnRESTScheme(t *testing.T) {
	// coturn use-auth-secret: password = base64(HMAC-SHA1(secret, username))
	m := hmac.New(sha1.New, []byte("s3cret"))
	m.Write([]byte("1700000000:S1"))
	want := base64.StdEncoding.EncodeToString(m.Sum(nil))
	if got := TURNCredential("s3cret", "1700000000:S1"); got != want {
		t.Fatalf("credential %q, want %q", got, want)
	}
}

func TestIceForMintsShortLivedTURN(t *testing.T) {
	s := &Server{cfg: Config{ICEServers: []string{"stun:a:3478"}, TURNURLs: []string{"turn:a:3478"}, TURNSecret: "k", TURNTTL: time.Hour}}
	now := time.Unix(1_700_000_000, 0)
	ice := s.iceFor("SABC", now)
	if len(ice) != 2 || ice[0].Username != "" {
		t.Fatalf("want STUN then TURN, got %+v", ice)
	}
	turn := ice[1]
	if turn.Username != "1700003600:SABC" {
		t.Fatalf("username %q", turn.Username)
	}
	if turn.Credential != TURNCredential("k", turn.Username) {
		t.Fatal("credential does not match the username")
	}
	// without a secret no TURN entry is handed out
	s.cfg.TURNSecret = ""
	if got := s.iceFor("SABC", now); len(got) != 1 {
		t.Fatalf("TURN without secret: %+v", got)
	}
}

func TestLimiterBlocksAfterRepeatedFailures(t *testing.T) {
	l := newLimiter()
	now := time.Now()
	for i := 1; i < maxFails; i++ {
		if l.fail("10.0.0.5", now) {
			t.Fatalf("blocked after %d failures", i)
		}
	}
	if !l.fail("10.0.0.5", now) {
		t.Fatal("not blocked after max failures")
	}
	if b, _ := l.blocked("10.0.0.5", now.Add(time.Minute)); !b {
		t.Fatal("block not in force")
	}
	if b, _ := l.blocked("10.0.0.6", now); b {
		t.Fatal("other address blocked")
	}
	if b, _ := l.blocked("10.0.0.5", now.Add(blockFor+time.Second)); b {
		t.Fatal("block did not expire")
	}
	l.success("10.0.0.5")
	if l.fails["10.0.0.5"] != nil {
		t.Fatal("success did not clear failures")
	}
}

func TestLimiterAllowSlidingWindow(t *testing.T) {
	l := newLimiter()
	now := time.Now()
	for i := 0; i < 3; i++ {
		if !l.allow("k", 3, time.Minute, now) {
			t.Fatalf("event %d refused", i)
		}
	}
	if l.allow("k", 3, time.Minute, now) {
		t.Fatal("fourth event allowed")
	}
	if !l.allow("k", 3, time.Minute, now.Add(61*time.Second)) {
		t.Fatal("window did not slide")
	}
	l.sweep(now.Add(2 * time.Hour))
	if len(l.hits) != 0 {
		t.Fatal("sweep kept old entries")
	}
}
