// Package aead is a thin AES-256-GCM wrapper. The session key from kex
// is a one-shot value, so payload encryption uses an all-zero nonce —
// the (key, nonce) pair is still unique per session.
//
// For any context where keys are reused, callers must supply a random
// 12-byte nonce via SealWithNonce / OpenWithNonce. The defaults
// (Seal / Open) intentionally hardcode the zero nonce to make the
// "one-shot key" contract explicit at the call-site.
package aead

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

const (
	KeySize   = 32 // AES-256
	NonceSize = 12 // GCM standard
	TagSize   = 16
)

var (
	ErrKeySize   = errors.New("aead: key must be 32 bytes")
	ErrNonceSize = errors.New("aead: nonce must be 12 bytes")
)

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, ErrKeySize
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Seal encrypts plaintext under key with an all-zero nonce. Use only
// when the key is one-shot (e.g. derived from a fresh ECDH exchange).
func Seal(key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceSize)
	return gcm.Seal(nil, nonce, plaintext, aad), nil
}

// Open decrypts ciphertext produced by Seal.
func Open(key, ciphertext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceSize)
	return gcm.Open(nil, nonce, ciphertext, aad)
}

// SealWithNonce is the explicit variant for re-used keys.
func SealWithNonce(key, nonce, plaintext, aad []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, ErrNonceSize
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, aad), nil
}

// OpenWithNonce is the explicit variant for re-used keys.
func OpenWithNonce(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, ErrNonceSize
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, aad)
}
