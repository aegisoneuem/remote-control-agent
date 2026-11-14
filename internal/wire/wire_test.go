package wire

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"
)

func TestSignVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	kid := KeyID(pub)
	trusted := map[string]ed25519.PublicKey{kid: pub}
	c := OpenRC{Type: "open_rc", SID: "S1", Session: "RC-1", Device: "PC-1", Operator: "Aegis Admin", Role: "controller", Mode: "control",
		Policy: DefaultPolicy(), Issued: time.Now().UnixMilli(), TTL: 60, Nonce: "n", KeyID: kid}
	b64, sig, err := Sign(priv, c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(trusted, b64, sig, kid, time.Now())
	if err != nil || got.Mode != "control" || got.Policy.Consent != "always" {
		t.Fatalf("valid command rejected: %v", err)
	}
	// tamper: change the mode inside the signed bytes
	raw, _ := base64.StdEncoding.DecodeString(b64)
	bad := []byte(string(raw))
	for i := range bad {
		if string(bad[i:i+9]) == `"control"` {
			copy(bad[i:], `"contrul"`)
			break
		}
	}
	if _, err := Verify(trusted, base64.StdEncoding.EncodeToString(bad), sig, kid, time.Now()); err != ErrBadSignature {
		t.Fatalf("tampered command accepted: %v", err)
	}
	// wrong key
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Verify(map[string]ed25519.PublicKey{kid: other}, b64, sig, kid, time.Now()); err != ErrBadSignature {
		t.Fatalf("command verified with the wrong key: %v", err)
	}
	// expired
	if _, err := Verify(trusted, b64, sig, kid, time.Now().Add(2*time.Minute)); err == nil {
		t.Fatal("expired command accepted")
	}
	// unknown key id
	if _, err := Verify(trusted, b64, sig, "deadbeef", time.Now()); err == nil {
		t.Fatal("unknown key id accepted")
	}
	if VerifyCode("S1") != VerifyCode("S1") || len(VerifyCode("S1")) != 7 {
		t.Fatal("verify code not stable")
	}
}
