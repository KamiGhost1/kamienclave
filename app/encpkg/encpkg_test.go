package encpkg

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/KamiGhost1/kamienclave/crypto/aead"
)

func fixtures(t *testing.T) (key []byte, pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	t.Helper()
	key = bytes.Repeat([]byte{0x5A}, aead.KeySize)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return key, pub, priv
}

func sampleManifest() *Manifest {
	return &Manifest{
		AppID:          "acme-backend",
		Version:        "1.0.0",
		Entrypoint:     "index.js",
		NodeSemver:     ">=20",
		EnvPassthrough: []string{"PORT", "DATABASE_URL"},
		Watermark:      "LCS-ACME-0001",
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	key, pub, priv := fixtures(t)
	payload := []byte("console.log('hello from bundle'); // pretend ncc bundle")

	pkg, err := Seal(sampleManifest(), payload, key, priv)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// Plaintext must not appear in the sealed package.
	if bytes.Contains(pkg, []byte("hello from bundle")) {
		t.Fatal("payload plaintext leaked into package")
	}
	if bytes.Contains(pkg, []byte("DATABASE_URL")) {
		t.Fatal("manifest plaintext leaked into package")
	}

	m, got, err := Open(pkg, key, pub)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch")
	}
	if m.AppID != "acme-backend" || m.Entrypoint != "index.js" || m.Watermark != "LCS-ACME-0001" {
		t.Fatalf("manifest mismatch: %+v", m)
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	key, pub, priv := fixtures(t)
	pkg, _ := Seal(sampleManifest(), []byte("x"), key, priv)

	wrong := bytes.Repeat([]byte{0x01}, aead.KeySize)
	if _, _, err := Open(pkg, wrong, pub); err == nil {
		t.Fatal("Open should fail with wrong key")
	}
}

func TestOpenRejectsWrongSigner(t *testing.T) {
	key, _, priv := fixtures(t)
	pkg, _ := Seal(sampleManifest(), []byte("x"), key, priv)

	otherPub, _, _ := ed25519.GenerateKey(nil)
	if _, _, err := Open(pkg, key, otherPub); !errors.Is(err, ErrBadSig) {
		t.Fatalf("got %v, want ErrBadSig", err)
	}
}

func TestOpenDetectsTamper(t *testing.T) {
	key, pub, priv := fixtures(t)
	pkg, _ := Seal(sampleManifest(), []byte("payload-bytes"), key, priv)

	// Flip a byte in the ciphertext body (before the signature).
	tampered := append([]byte(nil), pkg...)
	tampered[headerLen+2] ^= 0xFF
	if _, _, err := Open(tampered, key, pub); !errors.Is(err, ErrBadSig) {
		t.Fatalf("tamper in body: got %v, want ErrBadSig", err)
	}

	// Flip a byte in the header (also covered by the signature).
	tampered2 := append([]byte(nil), pkg...)
	tampered2[10] ^= 0xFF
	if _, _, err := Open(tampered2, key, pub); err == nil {
		t.Fatal("tamper in header should fail")
	}
}

func TestOpenRejectsTruncated(t *testing.T) {
	key, pub, priv := fixtures(t)
	pkg, _ := Seal(sampleManifest(), []byte("payload"), key, priv)
	if _, _, err := Open(pkg[:headerLen+10], key, pub); err == nil {
		t.Fatal("truncated package should fail")
	}
	if _, _, err := Open([]byte("tiny"), key, pub); !errors.Is(err, ErrTruncated) {
		t.Fatalf("got %v, want ErrTruncated", err)
	}
}

func TestSealRejectsBadKey(t *testing.T) {
	_, _, priv := fixtures(t)
	if _, err := Seal(sampleManifest(), nil, []byte("short"), priv); !errors.Is(err, ErrKeySize) {
		t.Fatalf("got %v, want ErrKeySize", err)
	}
}

func TestEmptyPayload(t *testing.T) {
	key, pub, priv := fixtures(t)
	pkg, err := Seal(sampleManifest(), nil, key, priv)
	if err != nil {
		t.Fatal(err)
	}
	_, got, err := Open(pkg, key, pub)
	if err != nil {
		t.Fatalf("Open empty payload: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty payload, got %d bytes", len(got))
	}
}
