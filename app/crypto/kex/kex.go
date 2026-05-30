// Package kex performs X25519 ephemeral key exchange and HKDF-SHA256
// derivation of a 32-byte session key.
//
// Both sides of the handshake call Generate() to produce a fresh keypair
// for each request and exchange public keys over the wire. The shared
// secret is mixed with a server-chosen salt and the fixed protocol
// info-string through HKDF-SHA256.
package kex

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/KamiGhost1/kamienclave/crypto/zeroize"
)

// Info is the HKDF info-string for the payload-encryption key. Both
// client and server must agree on this constant.
const Info = "kamienclave/v1/payload"

// SessionKeySize is the length of the derived symmetric key (256 bits).
const SessionKeySize = 32

var ErrEmptyShared = errors.New("kex: empty shared secret")

// Generate returns a fresh X25519 ephemeral keypair.
func Generate() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// ParsePublic parses a 32-byte X25519 public key as received from the peer.
func ParsePublic(raw []byte) (*ecdh.PublicKey, error) {
	return ecdh.X25519().NewPublicKey(raw)
}

// Derive computes the shared secret between priv and peerPub, mixes it
// with salt through HKDF-SHA256(info=Info) and returns a 32-byte session
// key. The intermediate shared secret is zeroised before returning.
func Derive(priv *ecdh.PrivateKey, peerPub *ecdh.PublicKey, salt []byte) ([]byte, error) {
	shared, err := priv.ECDH(peerPub)
	if err != nil {
		return nil, err
	}
	if len(shared) == 0 {
		return nil, ErrEmptyShared
	}
	defer zeroize.Bytes(shared)

	key := make([]byte, SessionKeySize)
	r := hkdf.New(sha256New, shared, salt, []byte(Info))
	if _, err := io.ReadFull(r, key); err != nil {
		zeroize.Bytes(key)
		return nil, err
	}
	return key, nil
}
