package integrity

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, body []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fakebin")
	if err := os.WriteFile(p, body, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestStampThenVerify(t *testing.T) {
	p := writeTemp(t, []byte("pretend this is an ELF binary body"))
	if err := Stamp(p); err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if err := verify(p); err != nil {
		t.Fatalf("verify after stamp: %v", err)
	}
}

func TestVerifyUnstamped(t *testing.T) {
	p := writeTemp(t, []byte("unstamped body"))
	if err := verify(p); !errors.Is(err, ErrNoExpectedHash) {
		t.Fatalf("got %v, want ErrNoExpectedHash", err)
	}
}

func TestVerifyDetectsTamper(t *testing.T) {
	p := writeTemp(t, []byte("original body bytes here"))
	if err := Stamp(p); err != nil {
		t.Fatal(err)
	}
	// Flip a body byte (offset 0) while leaving the trailer intact.
	data, _ := os.ReadFile(p)
	data[0] ^= 0xFF
	if err := os.WriteFile(p, data, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := verify(p); !errors.Is(err, ErrMismatch) {
		t.Fatalf("got %v, want ErrMismatch", err)
	}
}

func TestStampIsIdempotent(t *testing.T) {
	p := writeTemp(t, []byte("body"))
	if err := Stamp(p); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(p)
	if err := Stamp(p); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(p)
	if len(first) != len(second) {
		t.Fatalf("re-stamp changed size: %d -> %d", len(first), len(second))
	}
	if err := verify(p); err != nil {
		t.Fatalf("verify after re-stamp: %v", err)
	}
}
