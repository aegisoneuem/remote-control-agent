// Package rec is the encrypted session recording format shared by the agent and the server.
//
// The agent records the same screen messages it streams (internal/screen tile format), with a
// millisecond timestamp each, and encrypts them before they leave the device:
//
//   - per recording, a random 256-bit data key (DEK)
//   - every chunk sealed with AES-256-GCM under the DEK; nonce = 4 zero bytes || chunk number
//     (big endian), associated data = session id || chunk number, so chunks cannot be reordered
//     or moved to another recording
//   - the DEK is wrapped for the server's recording public key: X25519 with a fresh ephemeral key,
//     HKDF-SHA256(shared, salt = session id, info = "aegis-rc-rec-v1") -> KEK, AES-256-GCM
//
// The server stores ciphertext only. It unwraps the DEK at playback time, for a user with
// remotecontrol.recording.view, and records that in the audit log. In production the recording
// private key belongs in a KMS/HSM, separate from the signing key.
package rec

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

const info = "aegis-rc-rec-v1"

// Header travels with the recording: which key it was wrapped for, and the wrapped DEK.
type Header struct {
	KeyID   string `json:"key_id"`
	EphPub  string `json:"eph_pub"` // base64 X25519 public key
	Wrapped string `json:"wrapped"` // base64 AES-GCM(KEK, DEK)
}

// KeyID names a recording public key (first 6 bytes of its SHA-256, hex).
func KeyID(pub []byte) string { h := sha256.Sum256(pub); return hex.EncodeToString(h[:6]) }

func gcm(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func kek(shared []byte, session string) ([]byte, error) {
	return hkdf.Key(sha256.New, shared, []byte(session), info, 32)
}

// Sealer encrypts the chunks of one recording on the agent.
type Sealer struct {
	session string
	aead    cipher.AEAD
}

// NewSealer creates the DEK and wraps it for the server's recording public key.
func NewSealer(serverPub []byte, keyID, session string) (*Sealer, Header, error) {
	pub, err := ecdh.X25519().NewPublicKey(serverPub)
	if err != nil {
		return nil, Header{}, fmt.Errorf("recording key: %w", err)
	}
	if KeyID(serverPub) != keyID {
		return nil, Header{}, errors.New("recording key id does not match the key")
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, Header{}, err
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return nil, Header{}, err
	}
	k, err := kek(shared, session)
	if err != nil {
		return nil, Header{}, err
	}
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, Header{}, err
	}
	wa, err := gcm(k)
	if err != nil {
		return nil, Header{}, err
	}
	wrapped := wa.Seal(nil, make([]byte, wa.NonceSize()), dek, []byte(session)) // the KEK is single use
	aead, err := gcm(dek)
	if err != nil {
		return nil, Header{}, err
	}
	return &Sealer{session: session, aead: aead}, Header{KeyID: keyID, EphPub: base64.StdEncoding.EncodeToString(eph.PublicKey().Bytes()),
		Wrapped: base64.StdEncoding.EncodeToString(wrapped)}, nil
}

func nonceAD(session string, n uint64, size int) ([]byte, []byte) {
	nonce := make([]byte, size)
	binary.BigEndian.PutUint64(nonce[size-8:], n)
	ad := append([]byte(session), nonce[size-8:]...)
	return nonce, ad
}

// Seal encrypts chunk n. Chunk numbers must be unique within a recording.
func (s *Sealer) Seal(n uint64, plain []byte) []byte {
	nonce, ad := nonceAD(s.session, n, s.aead.NonceSize())
	return s.aead.Seal(nil, nonce, plain, ad)
}

// Opener decrypts the chunks of one recording on the server.
type Opener struct {
	session string
	aead    cipher.AEAD
}

func NewOpener(priv *ecdh.PrivateKey, h Header, session string) (*Opener, error) {
	eb, err := base64.StdEncoding.DecodeString(h.EphPub)
	if err != nil {
		return nil, err
	}
	eph, err := ecdh.X25519().NewPublicKey(eb)
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(eph)
	if err != nil {
		return nil, err
	}
	k, err := kek(shared, session)
	if err != nil {
		return nil, err
	}
	wa, err := gcm(k)
	if err != nil {
		return nil, err
	}
	wb, err := base64.StdEncoding.DecodeString(h.Wrapped)
	if err != nil {
		return nil, err
	}
	dek, err := wa.Open(nil, make([]byte, wa.NonceSize()), wb, []byte(session))
	if err != nil {
		return nil, errors.New("recording key does not unwrap (wrong server key or tampered header)")
	}
	aead, err := gcm(dek)
	if err != nil {
		return nil, err
	}
	return &Opener{session: session, aead: aead}, nil
}

func (o *Opener) Open(n uint64, sealed []byte) ([]byte, error) {
	nonce, ad := nonceAD(o.session, n, o.aead.NonceSize())
	p, err := o.aead.Open(nil, nonce, sealed, ad)
	if err != nil {
		return nil, fmt.Errorf("chunk %d failed authentication", n)
	}
	return p, nil
}

/* plaintext frame format inside a chunk: repeated [u32 t_ms][u32 len][len bytes screen message] */

func AppendFrame(buf []byte, tms uint32, msg []byte) []byte {
	var h [8]byte
	binary.BigEndian.PutUint32(h[:4], tms)
	binary.BigEndian.PutUint32(h[4:], uint32(len(msg)))
	return append(append(buf, h[:]...), msg...)
}

type Frame struct {
	TMS uint32
	Msg []byte
}

func ParseFrames(b []byte) ([]Frame, error) {
	var out []Frame
	for len(b) > 0 {
		if len(b) < 8 {
			return out, errors.New("truncated frame header")
		}
		t, n := binary.BigEndian.Uint32(b[:4]), binary.BigEndian.Uint32(b[4:8])
		if uint32(len(b)-8) < n {
			return out, errors.New("truncated frame")
		}
		out = append(out, Frame{TMS: t, Msg: b[8 : 8+n]})
		b = b[8+n:]
	}
	return out, nil
}

/* server key file */

// LoadOrCreateKey reads the recording private key (base64 X25519 scalar) or creates it.
func LoadOrCreateKey(path string) (*ecdh.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		k, gerr := ecdh.X25519().GenerateKey(rand.Reader)
		if gerr != nil {
			return nil, gerr
		}
		if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(k.Bytes())), 0o600); err != nil {
			return nil, err
		}
		return k, nil
	} else if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, errors.New("recording.key is corrupt")
	}
	return ecdh.X25519().NewPrivateKey(raw)
}
