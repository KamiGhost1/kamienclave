package kex

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestDeriveRoundTrip(t *testing.T) {
	clientPriv, err := Generate()
	if err != nil {
		t.Fatalf("client gen: %v", err)
	}
	serverPriv, err := Generate()
	if err != nil {
		t.Fatalf("server gen: %v", err)
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("rand: %v", err)
	}

	k1, err := Derive(clientPriv, serverPriv.PublicKey(), salt)
	if err != nil {
		t.Fatalf("client derive: %v", err)
	}
	k2, err := Derive(serverPriv, clientPriv.PublicKey(), salt)
	if err != nil {
		t.Fatalf("server derive: %v", err)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatalf("derived keys differ: %x vs %x", k1, k2)
	}
	if len(k1) != SessionKeySize {
		t.Fatalf("len %d, want %d", len(k1), SessionKeySize)
	}
}

func TestDeriveDifferentSaltsDiverge(t *testing.T) {
	a, _ := Generate()
	b, _ := Generate()

	k1, _ := Derive(a, b.PublicKey(), []byte("saltA"))
	k2, _ := Derive(a, b.PublicKey(), []byte("saltB"))
	if bytes.Equal(k1, k2) {
		t.Fatal("different salts must derive different keys")
	}
}

func TestParsePublicRoundTrip(t *testing.T) {
	priv, _ := Generate()
	pub := priv.PublicKey()
	parsed, err := ParsePublic(pub.Bytes())
	if err != nil {
		t.Fatalf("ParsePublic: %v", err)
	}
	if !bytes.Equal(parsed.Bytes(), pub.Bytes()) {
		t.Fatal("public key bytes round-trip differs")
	}
}
