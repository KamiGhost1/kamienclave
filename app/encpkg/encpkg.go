// Package encpkg implements the `.encpkg` container for full-application
// delivery (режим B, docs/DRAFT-fullapp-delivery.md §3): a signed,
// encrypted envelope carrying a manifest plus an opaque application
// payload (typically a single-file ncc bundle).
//
// Layout (all integers big-endian):
//
//	magic        "ENCPKG1\0"            (8 bytes)
//	version      u16
//	flags        u16
//	manifestNonce [12]byte              (GCM nonce for the manifest)
//	payloadNonce  [12]byte              (GCM nonce for the payload)
//	manifestLen  u32                    (len of encrypted manifest, incl tag)
//	payloadLen   u64                    (len of encrypted payload, incl tag)
//	------------------------------------ end of header (authenticated as AAD)
//	manifestCT   [manifestLen]byte      AES-256-GCM(key, manifestNonce, json, aad=header)
//	payloadCT    [payloadLen]byte       AES-256-GCM(key, payloadNonce, payload, aad=header)
//	sig          [64]byte               Ed25519(serverPriv) over all preceding bytes
//
// Both sections are encrypted with the per-license app key (carried in
// the client bundle). The whole envelope is signed by the server so the
// client can verify authenticity before spending effort on decryption,
// and reject any tampering. The header is bound into each section via the
// AEAD additional data, so lengths/nonces cannot be swapped undetected.
package encpkg

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/KamiGhost1/kamienclave/crypto/aead"
	"github.com/KamiGhost1/kamienclave/crypto/sign"
)

const (
	magic         = "ENCPKG1\x00"
	magicLen      = 8
	formatVersion = 1
	headerLen     = magicLen + 2 + 2 + aead.NonceSize + aead.NonceSize + 4 + 8
)

var (
	ErrFormat    = errors.New("encpkg: malformed package")
	ErrVersion   = errors.New("encpkg: unsupported version")
	ErrBadSig    = errors.New("encpkg: signature verification failed")
	ErrKeySize   = errors.New("encpkg: key must be 32 bytes")
	ErrTruncated = errors.New("encpkg: truncated package")
)

// Manifest describes how to run the delivered application. It is JSON so
// it is trivial to audit and extend; it travels encrypted inside the
// envelope.
type Manifest struct {
	AppID          string   `json:"app_id"`
	Version        string   `json:"version"`
	Entrypoint     string   `json:"entrypoint"`                // logical name, e.g. "index.js"
	NodeSemver     string   `json:"node_semver,omitempty"`     // required runtime range
	Args           []string `json:"args,omitempty"`            // extra node args
	EnvPassthrough []string `json:"env_passthrough,omitempty"` // env var names to forward
	Watermark      string   `json:"watermark,omitempty"`       // per-license fingerprint
	PayloadSHA256  string   `json:"payload_sha256,omitempty"`  // hex, integrity of plaintext payload
}

// Seal builds a signed, encrypted .encpkg from a manifest and payload.
// key is the per-license app key (32 bytes); signKey is the server's
// Ed25519 private key.
func Seal(manifest *Manifest, payload, key []byte, signKey ed25519.PrivateKey) ([]byte, error) {
	if len(key) != aead.KeySize {
		return nil, ErrKeySize
	}
	if manifest == nil {
		return nil, fmt.Errorf("%w: nil manifest", ErrFormat)
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}

	mNonce := make([]byte, aead.NonceSize)
	pNonce := make([]byte, aead.NonceSize)
	if _, err := rand.Read(mNonce); err != nil {
		return nil, err
	}
	if _, err := rand.Read(pNonce); err != nil {
		return nil, err
	}

	// Encrypt with the header as AAD. We build the header first (lengths
	// depend on ciphertext sizes, which include the GCM tag), so do a
	// dry pass: GCM ciphertext length = plaintext + TagSize.
	mLen := len(manifestJSON) + aead.TagSize
	pLen := len(payload) + aead.TagSize
	header := buildHeader(mNonce, pNonce, uint32(mLen), uint64(pLen))

	mCT, err := aead.SealWithNonce(key, mNonce, manifestJSON, header)
	if err != nil {
		return nil, err
	}
	pCT, err := aead.SealWithNonce(key, pNonce, payload, header)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(header)+len(mCT)+len(pCT)+sign.SignatureSize)
	out = append(out, header...)
	out = append(out, mCT...)
	out = append(out, pCT...)

	sig, err := sign.Sign(signKey, out)
	if err != nil {
		return nil, err
	}
	out = append(out, sig...)
	return out, nil
}

// Open verifies the server signature, then decrypts and returns the
// manifest and payload. verifyKey is the server's Ed25519 public key;
// key is the per-license app key.
func Open(pkg, key []byte, verifyKey ed25519.PublicKey) (*Manifest, []byte, error) {
	if len(key) != aead.KeySize {
		return nil, nil, ErrKeySize
	}
	if len(pkg) < headerLen+sign.SignatureSize {
		return nil, nil, ErrTruncated
	}

	// Split signature and verify over everything before it.
	signedLen := len(pkg) - sign.SignatureSize
	body, sig := pkg[:signedLen], pkg[signedLen:]
	if err := sign.Verify(verifyKey, body, sig); err != nil {
		return nil, nil, ErrBadSig
	}

	r := &reader{buf: body}
	if !r.match([]byte(magic)) {
		return nil, nil, fmt.Errorf("%w: bad magic", ErrFormat)
	}
	ver, _ := r.u16()
	if ver != formatVersion {
		return nil, nil, ErrVersion
	}
	r.u16() // flags (reserved)
	mNonce, ok1 := r.bytes(aead.NonceSize)
	pNonce, ok2 := r.bytes(aead.NonceSize)
	mLen, ok3 := r.u32()
	pLen, ok4 := r.u64()
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return nil, nil, ErrTruncated
	}

	header := body[:headerLen]
	mCT, ok := r.bytes(int(mLen))
	if !ok {
		return nil, nil, ErrTruncated
	}
	pCT, ok := r.bytes(int(pLen))
	if !ok {
		return nil, nil, ErrTruncated
	}
	if r.pos != len(body) {
		return nil, nil, fmt.Errorf("%w: trailing bytes", ErrFormat)
	}

	manifestJSON, err := aead.OpenWithNonce(key, mNonce, mCT, header)
	if err != nil {
		return nil, nil, fmt.Errorf("encpkg: manifest decrypt: %w", err)
	}
	payload, err := aead.OpenWithNonce(key, pNonce, pCT, header)
	if err != nil {
		return nil, nil, fmt.Errorf("encpkg: payload decrypt: %w", err)
	}

	var m Manifest
	if err := json.Unmarshal(manifestJSON, &m); err != nil {
		return nil, nil, fmt.Errorf("encpkg: manifest parse: %w", err)
	}
	return &m, payload, nil
}

func buildHeader(mNonce, pNonce []byte, mLen uint32, pLen uint64) []byte {
	h := make([]byte, 0, headerLen)
	h = append(h, []byte(magic)...)
	h = binary.BigEndian.AppendUint16(h, formatVersion)
	h = binary.BigEndian.AppendUint16(h, 0 /* flags */)
	h = append(h, mNonce...)
	h = append(h, pNonce...)
	h = binary.BigEndian.AppendUint32(h, mLen)
	h = binary.BigEndian.AppendUint64(h, pLen)
	return h
}

// reader is a tiny bounds-checked cursor.
type reader struct {
	buf []byte
	pos int
}

func (r *reader) match(b []byte) bool {
	if r.pos+len(b) > len(r.buf) {
		return false
	}
	for i := range b {
		if r.buf[r.pos+i] != b[i] {
			return false
		}
	}
	r.pos += len(b)
	return true
}

func (r *reader) u16() (uint16, bool) {
	if r.pos+2 > len(r.buf) {
		return 0, false
	}
	v := binary.BigEndian.Uint16(r.buf[r.pos:])
	r.pos += 2
	return v, true
}

func (r *reader) u32() (uint32, bool) {
	if r.pos+4 > len(r.buf) {
		return 0, false
	}
	v := binary.BigEndian.Uint32(r.buf[r.pos:])
	r.pos += 4
	return v, true
}

func (r *reader) u64() (uint64, bool) {
	if r.pos+8 > len(r.buf) {
		return 0, false
	}
	v := binary.BigEndian.Uint64(r.buf[r.pos:])
	r.pos += 8
	return v, true
}

func (r *reader) bytes(n int) ([]byte, bool) {
	if n < 0 || r.pos+n > len(r.buf) {
		return nil, false
	}
	b := r.buf[r.pos : r.pos+n]
	r.pos += n
	return b, true
}
