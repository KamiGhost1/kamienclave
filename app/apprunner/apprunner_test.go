package apprunner_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/KamiGhost1/kamienclave/apprunner"
	"github.com/KamiGhost1/kamienclave/crypto/aead"
	"github.com/KamiGhost1/kamienclave/encpkg"
)

type fakeLauncher struct {
	launched apprunner.App
	called   bool
}

func (f *fakeLauncher) Launch(_ context.Context, app apprunner.App) error {
	f.called = true
	f.launched = app
	return nil
}

func seal(t *testing.T, m *encpkg.Manifest, payload, key []byte, priv ed25519.PrivateKey) []byte {
	t.Helper()
	pkg, err := encpkg.Seal(m, payload, key, priv)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return pkg
}

func TestRunHappyPath(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, aead.KeySize)
	pub, priv, _ := ed25519.GenerateKey(nil)
	payload := []byte("console.log('app');")
	sum := sha256.Sum256(payload)

	pkg := seal(t, &encpkg.Manifest{
		AppID:          "app",
		Entrypoint:     "index.js",
		EnvPassthrough: []string{"PORT", "MISSING"},
		PayloadSHA256:  hex.EncodeToString(sum[:]),
	}, payload, key, priv)

	env := map[string]string{"PORT": "8080"}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }

	fl := &fakeLauncher{}
	if err := apprunner.Run(context.Background(), fl, pkg, key, pub, lookup); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !fl.called {
		t.Fatal("launcher not called")
	}
	if fl.launched.Manifest.Entrypoint != "index.js" {
		t.Fatalf("entrypoint = %q", fl.launched.Manifest.Entrypoint)
	}
	if fl.launched.Env["PORT"] != "8080" {
		t.Fatalf("env PORT = %q, want 8080", fl.launched.Env["PORT"])
	}
	if _, ok := fl.launched.Env["MISSING"]; ok {
		t.Fatal("MISSING should not be resolved")
	}
}

func TestOpenDetectsIntegrityMismatch(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, aead.KeySize)
	pub, priv, _ := ed25519.GenerateKey(nil)
	// Manifest claims a sha256 that doesn't match the payload.
	pkg := seal(t, &encpkg.Manifest{
		Entrypoint:    "index.js",
		PayloadSHA256: hex.EncodeToString(make([]byte, 32)),
	}, []byte("real-bytes"), key, priv)

	if _, err := apprunner.Open(pkg, key, pub, nil); !errors.Is(err, apprunner.ErrIntegrity) {
		t.Fatalf("got %v, want ErrIntegrity", err)
	}
}

func TestOpenRejectsEmptyEntrypoint(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, aead.KeySize)
	pub, priv, _ := ed25519.GenerateKey(nil)
	pkg := seal(t, &encpkg.Manifest{Entrypoint: ""}, []byte("x"), key, priv)
	if _, err := apprunner.Open(pkg, key, pub, nil); !errors.Is(err, apprunner.ErrManifest) {
		t.Fatalf("got %v, want ErrManifest", err)
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, aead.KeySize)
	pub, priv, _ := ed25519.GenerateKey(nil)
	pkg := seal(t, &encpkg.Manifest{Entrypoint: "i.js"}, []byte("x"), key, priv)
	wrong := bytes.Repeat([]byte{0x01}, aead.KeySize)
	if _, err := apprunner.Open(pkg, wrong, pub, nil); err == nil {
		t.Fatal("wrong key should fail")
	}
}
