//go:build !backend

package cliargs_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KamiGhost1/kamienclave/crypto/sign"
	"github.com/KamiGhost1/kamienclave/internal/buildinfo"
	"github.com/KamiGhost1/kamienclave/internal/cliargs"
	"github.com/KamiGhost1/kamienclave/license"
	"github.com/KamiGhost1/kamienclave/license/blob"
	"github.com/KamiGhost1/kamienclave/transport/mockserver"
	"github.com/KamiGhost1/kamienclave/transport/pin"
)

// TestRunCommandEndToEnd drives the actual `run` cobra command against an
// in-process mock licence server: unlock a sealed bundle, fetch over
// TLS+pin, execute the payload, and print the result. This is the
// default (public/goja) execution path.
func TestRunCommandEndToEnd(t *testing.T) {
	const payload = `log("cli integ ok"); 6 * 7`

	srv, err := mockserver.New([]byte(payload))
	if err != nil {
		t.Fatalf("mockserver: %v", err)
	}
	defer srv.Close()

	clientKey, err := sign.GenerateKey()
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	srv.RegisterClient(clientKey.Public().(ed25519.PublicKey))

	leaf := srv.HTTP.Certificate()

	// Seal a bundle pointing at the mock server.
	bundle := &license.Bundle{
		LicenseID:  "LCS-CLI",
		ServerURL:  srv.HTTP.URL,
		ServerPub:  srv.ServerSigningKey.Public().(ed25519.PublicKey),
		SPKIPin:    pin.Compute(leaf),
		ClientPriv: clientKey,
	}
	pass := "cli-test-pass"
	enc, err := license.Seal([]byte(pass), bundle, blob.KDFParams{Time: 1, MemoryKiB: 8 * 1024, Parallelism: 1})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	dir := t.TempDir()
	blobPath := filepath.Join(dir, "license.lic")
	if err := os.WriteFile(blobPath, enc, 0o600); err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(dir, "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	// Non-interactive passphrase.
	t.Setenv("ENCLAVE_PASSPHRASE", pass)

	root := cliargs.NewRootCommand(buildinfo.Info{Version: "test", Variant: "public"})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"run", "--license-file", blobPath, "--ca", caPath, "-t", "10s"})

	if err := root.Execute(); err != nil {
		t.Fatalf("run command failed: %v\noutput:\n%s", err, out.String())
	}

	got := out.String()
	if !strings.Contains(got, "cli integ ok") {
		t.Errorf("missing payload log output; got:\n%s", got)
	}
	if !strings.Contains(got, "result: 42") {
		t.Errorf("missing completion result; got:\n%s", got)
	}
}
