package license_test

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"github.com/KamiGhost1/kamienclave/crypto/sign"
	"github.com/KamiGhost1/kamienclave/crypto/zeroize"
	"github.com/KamiGhost1/kamienclave/license"
	"github.com/KamiGhost1/kamienclave/license/blob"
	"github.com/KamiGhost1/kamienclave/runtime/host"
	"github.com/KamiGhost1/kamienclave/runtime/vm"
	"github.com/KamiGhost1/kamienclave/transport"
	"github.com/KamiGhost1/kamienclave/transport/mockserver"
	"github.com/KamiGhost1/kamienclave/transport/pin"
)

func fastParams() blob.KDFParams {
	return blob.KDFParams{Time: 1, MemoryKiB: 8 * 1024, Parallelism: 1}
}

// TestEndToEndViaLicence wires every stage 1-4 piece together:
// build a bundle, seal it, unlock, fetch via TLS-with-pinning, AEAD-open
// the reply, run it in the VM, observe the completion value.
func TestEndToEndViaLicence(t *testing.T) {
	const payloadJS = `log("integration: hi"); 21 * 2`

	// 1. Mock server with its own keypair.
	srv, err := mockserver.New([]byte(payloadJS))
	if err != nil {
		t.Fatalf("mockserver: %v", err)
	}
	defer srv.Close()

	// 2. Client keypair.
	clientKey, err := sign.GenerateKey()
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	srv.RegisterClient(clientKey.Public().(ed25519.PublicKey))

	// 3. Build & seal a bundle pointing at the mock.
	leaf := srv.HTTP.Certificate()
	bundle := &license.Bundle{
		LicenseID:  "LCS-INTEG",
		ServerURL:  srv.HTTP.URL,
		ServerPub:  srv.ServerSigningKey.Public().(ed25519.PublicKey),
		SPKIPin:    pin.Compute(leaf),
		ClientPriv: clientKey,
	}
	pass := []byte("super-secret-passphrase")
	enc, err := license.Seal(pass, bundle, fastParams())
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// 4. Unlock from scratch — as the real CLI would.
	unlocked, err := license.Unlock(pass, enc)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	defer unlocked.Wipe()

	// 5. Trust the test server's leaf cert.
	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	cli, err := transport.NewClient(transport.Config{
		ServerURL: unlocked.ServerURL,
		Pins:      pin.NewSet(unlocked.SPKIPin),
		RootCAs:   &tls.Config{RootCAs: pool},
		Timeout:   5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// 6. Fetch + decrypt.
	plain, err := transport.Fetch(context.Background(), cli, transport.FetchParams{
		Product:          "enclave",
		Build:            "backend",
		ClientVersion:    "0.0.0-test",
		LicenseID:        unlocked.LicenseID,
		ClientSigningKey: unlocked.ClientPriv,
		ServerVerifyKey:  unlocked.ServerPub,
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	defer zeroize.Bytes(plain)

	if string(plain) != payloadJS {
		t.Fatalf("payload mismatch:\n got %q\nwant %q", plain, payloadJS)
	}

	// 7. Run in VM.
	v := vm.New(vm.Options{})
	defer v.Close()

	b := host.New()
	if err := b.Install(v); err != nil {
		t.Fatalf("install host: %v", err)
	}

	val, err := v.Run(context.Background(), "integ.js", plain)
	if err != nil {
		t.Fatalf("VM Run: %v", err)
	}
	if val.ToInteger() != 42 {
		t.Fatalf("VM completion = %v, want 42", val)
	}
}
