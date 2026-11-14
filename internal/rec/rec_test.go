package rec

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	srv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	pub := srv.PublicKey().Bytes()
	s, h, err := NewSealer(pub, KeyID(pub), "RC-ABC123")
	if err != nil {
		t.Fatal(err)
	}
	plain := AppendFrame(AppendFrame(nil, 0, []byte{1, 2, 3}), 120, []byte("tile"))
	c0, c1 := s.Seal(0, plain), s.Seal(1, []byte("second"))
	if bytes.Contains(c0, []byte("tile")) {
		t.Fatal("ciphertext contains plaintext")
	}
	o, err := NewOpener(srv, h, "RC-ABC123")
	if err != nil {
		t.Fatal(err)
	}
	p0, err := o.Open(0, c0)
	if err != nil || !bytes.Equal(p0, plain) {
		t.Fatalf("chunk 0: %v", err)
	}
	fr, err := ParseFrames(p0)
	if err != nil || len(fr) != 2 || fr[1].TMS != 120 || string(fr[1].Msg) != "tile" {
		t.Fatalf("frames %+v %v", fr, err)
	}
	if _, err := o.Open(0, c1); err == nil {
		t.Fatal("chunk opened under the wrong number (reorder not detected)")
	}
	if _, err := NewOpener(srv, h, "RC-OTHER"); err == nil {
		t.Fatal("header opened for another session")
	}
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if _, err := NewOpener(other, h, "RC-ABC123"); err == nil {
		t.Fatal("opened with the wrong server key")
	}
	c0[len(c0)-1] ^= 1
	if _, err := o.Open(0, c0); err == nil {
		t.Fatal("tampered chunk accepted")
	}
	if _, _, err := NewSealer(pub, "000000000000", "RC-X"); err == nil {
		t.Fatal("key id mismatch accepted")
	}
}
