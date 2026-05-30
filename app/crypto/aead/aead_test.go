package aead

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

func TestSealOpenRoundTrip(t *testing.T) {
	key := randBytes(t, KeySize)
	pt := []byte("very-secret-payload")
	aad := []byte("context")

	ct, err := Seal(key, pt, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Equal(ct, pt) {
		t.Fatal("ciphertext == plaintext")
	}
	got, err := Open(key, ct, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("decrypt mismatch: %q vs %q", got, pt)
	}
}

func TestOpenRejectsTampered(t *testing.T) {
	key := randBytes(t, KeySize)
	ct, _ := Seal(key, []byte("hello"), nil)
	ct[0] ^= 0x01
	if _, err := Open(key, ct, nil); err == nil {
		t.Fatal("Open should reject tampered ciphertext")
	}
}

func TestOpenRejectsWrongAAD(t *testing.T) {
	key := randBytes(t, KeySize)
	ct, _ := Seal(key, []byte("hello"), []byte("aad"))
	if _, err := Open(key, ct, []byte("other")); err == nil {
		t.Fatal("Open should reject wrong AAD")
	}
}

func TestSealRejectsBadKeySize(t *testing.T) {
	if _, err := Seal(make([]byte, 16), nil, nil); err != ErrKeySize {
		t.Fatalf("got %v, want ErrKeySize", err)
	}
}

func TestSealWithNonce(t *testing.T) {
	key := randBytes(t, KeySize)
	nonce := randBytes(t, NonceSize)
	ct, err := SealWithNonce(key, nonce, []byte("x"), nil)
	if err != nil {
		t.Fatalf("SealWithNonce: %v", err)
	}
	pt, err := OpenWithNonce(key, nonce, ct, nil)
	if err != nil {
		t.Fatalf("OpenWithNonce: %v", err)
	}
	if string(pt) != "x" {
		t.Fatalf("decrypt: %q", pt)
	}
}

func TestSealWithNonceBadNonce(t *testing.T) {
	key := randBytes(t, KeySize)
	if _, err := SealWithNonce(key, []byte{1, 2, 3}, nil, nil); err != ErrNonceSize {
		t.Fatalf("got %v, want ErrNonceSize", err)
	}
}
