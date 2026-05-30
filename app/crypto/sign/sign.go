// Package sign implements Ed25519 (RFC 8032) signing and verification
// over arbitrary byte messages.
//
// Ed25519 is chosen over ECDSA P-256 (draft 0.1): it is deterministic —
// there is no per-signature nonce to leak — which removes the single
// most common catastrophic failure mode of ECDSA. It is also faster,
// has fixed 64-byte signatures, and shares the same Curve25519 family
// as the X25519 key exchange already used by the session layer.
//
// The signature is the raw 64-byte Ed25519 value; Ed25519 hashes the
// message internally (SHA-512), so callers pass the message as-is with
// no pre-hashing.
package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
)

const (
	// SignatureSize is the fixed Ed25519 signature length.
	SignatureSize = ed25519.SignatureSize // 64
	// PublicKeySize / PrivateKeySize are re-exported for callers that
	// validate lengths before parsing.
	PublicKeySize  = ed25519.PublicKeySize  // 32
	PrivateKeySize = ed25519.PrivateKeySize // 64 (seed || public)
)

var (
	ErrInvalidSignature = errors.New("sign: invalid signature")
	ErrWrongKey         = errors.New("sign: malformed key")
)

// GenerateKey produces a fresh Ed25519 keypair using crypto/rand. The
// private key embeds its public half (see crypto/ed25519).
func GenerateKey() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

// Sign returns the 64-byte Ed25519 signature of msg under priv.
func Sign(priv ed25519.PrivateKey, msg []byte) ([]byte, error) {
	if len(priv) != PrivateKeySize {
		return nil, ErrWrongKey
	}
	return ed25519.Sign(priv, msg), nil
}

// Verify checks sig against msg under pub. Returns ErrInvalidSignature
// on any mismatch and ErrWrongKey for a malformed public key.
func Verify(pub ed25519.PublicKey, msg, sig []byte) error {
	if len(pub) != PublicKeySize {
		return ErrWrongKey
	}
	if len(sig) != SignatureSize {
		return ErrInvalidSignature
	}
	if !ed25519.Verify(pub, msg, sig) {
		return ErrInvalidSignature
	}
	return nil
}
