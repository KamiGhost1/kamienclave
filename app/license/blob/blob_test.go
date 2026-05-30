package blob

import (
	"bytes"
	"testing"
)

// Use a deliberately small set of Argon2 parameters in tests so unit
// tests stay fast. Production callers should pass blob.Default().
func fastParams() KDFParams {
	return KDFParams{Time: 1, MemoryKiB: 8 * 1024, Parallelism: 1}
}

func TestSealOpenRoundTrip(t *testing.T) {
	pass := []byte("correct horse battery staple")
	pt := []byte(`{"license":"LCS-EXAMPLE","priv":"..."}`)

	out, err := Seal(pass, pt, fastParams())
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(out, pt) {
		t.Fatal("plaintext leaks into ciphertext")
	}

	got, err := Open(pass, out)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("round-trip differs: %q vs %q", got, pt)
	}
}

func TestOpenRejectsWrongPassphrase(t *testing.T) {
	pass := []byte("right")
	out, _ := Seal(pass, []byte("hello"), fastParams())
	if _, err := Open([]byte("wrong"), out); err == nil {
		t.Fatal("Open should fail with wrong passphrase")
	}
}

func TestOpenRejectsBadMagic(t *testing.T) {
	out, _ := Seal([]byte("x"), []byte("hi"), fastParams())
	out[0] = 'X'
	if _, err := Open([]byte("x"), out); err != ErrBadMagic {
		t.Fatalf("got %v, want ErrBadMagic", err)
	}
}

func TestOpenRejectsTamperedHeader(t *testing.T) {
	pass := []byte("x")
	out, _ := Seal(pass, []byte("hi"), fastParams())
	// Flip a bit in the salt — AEAD auth tag should refuse the result
	// because the header is AAD.
	out[20] ^= 0x01
	if _, err := Open(pass, out); err == nil {
		t.Fatal("tampered header must fail")
	}
}

func TestOpenRejectsTruncated(t *testing.T) {
	pass := []byte("x")
	out, _ := Seal(pass, []byte("hi"), fastParams())
	if _, err := Open(pass, out[:5]); err == nil {
		t.Fatal("truncated must fail")
	}
}

func TestSealRejectsEmpty(t *testing.T) {
	if _, err := Seal(nil, []byte("x"), fastParams()); err != ErrEmptyPassphrase {
		t.Fatalf("got %v, want ErrEmptyPassphrase", err)
	}
}

func TestDeterministicBlobsDiverge(t *testing.T) {
	// Different runs with the same passphrase+plaintext must produce
	// different blobs (random salt + nonce). This catches accidental
	// determinism if either source loses its entropy.
	pass := []byte("x")
	pt := []byte("hello")
	a, _ := Seal(pass, pt, fastParams())
	b, _ := Seal(pass, pt, fastParams())
	if bytes.Equal(a, b) {
		t.Fatal("two seals must differ")
	}
}
