package transport_test

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/KamiGhost1/kamienclave/crypto/sign"
	"github.com/KamiGhost1/kamienclave/transport"
	"github.com/KamiGhost1/kamienclave/transport/mockserver"
	"github.com/KamiGhost1/kamienclave/transport/pin"
)

const samplePayload = `log("hello from server"); "result-from-server"`

func pub(priv ed25519.PrivateKey) ed25519.PublicKey {
	return priv.Public().(ed25519.PublicKey)
}

func newClientFor(t *testing.T, srv *mockserver.Server, allowAny bool) *transport.Client {
	t.Helper()

	leaf := srv.HTTP.Certificate()
	p := pin.Compute(leaf)

	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	cli, err := transport.NewClient(transport.Config{
		ServerURL:          srv.HTTP.URL,
		Pins:               pin.NewSet(p),
		AllowAnyServerCert: allowAny,
		RootCAs: &tls.Config{
			RootCAs: pool,
		},
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return cli
}

func TestFetchHappyPath(t *testing.T) {
	srv, err := mockserver.New([]byte(samplePayload))
	if err != nil {
		t.Fatalf("mockserver: %v", err)
	}
	defer srv.Close()

	clientKey, err := sign.GenerateKey()
	if err != nil {
		t.Fatalf("client gen: %v", err)
	}
	srv.RegisterClient(pub(clientKey))

	cli := newClientFor(t, srv, false)

	got, err := transport.Fetch(context.Background(), cli, transport.FetchParams{
		Product:          "enclave",
		Build:            "backend",
		ClientVersion:    "0.0.0-dev",
		LicenseID:        "LCS-TEST",
		ClientSigningKey: clientKey,
		ServerVerifyKey:  pub(srv.ServerSigningKey),
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(got) != samplePayload {
		t.Fatalf("payload mismatch:\n got %q\nwant %q", got, samplePayload)
	}
}

func TestFetchRejectsBadPin(t *testing.T) {
	srv, err := mockserver.New([]byte(samplePayload))
	if err != nil {
		t.Fatalf("mockserver: %v", err)
	}
	defer srv.Close()

	clientKey, _ := sign.GenerateKey()
	srv.RegisterClient(pub(clientKey))

	// Build a client with a bogus pin (all zeros).
	pool := x509.NewCertPool()
	pool.AddCert(srv.HTTP.Certificate())

	cli, err := transport.NewClient(transport.Config{
		ServerURL: srv.HTTP.URL,
		Pins:      pin.NewSet(pin.Pin{}),
		RootCAs:   &tls.Config{RootCAs: pool},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = transport.Fetch(context.Background(), cli, transport.FetchParams{
		Product:          "enclave",
		Build:            "backend",
		ClientVersion:    "0.0.0-dev",
		LicenseID:        "LCS-TEST",
		ClientSigningKey: clientKey,
		ServerVerifyKey:  pub(srv.ServerSigningKey),
	})
	if err == nil {
		t.Fatal("Fetch should fail on bad SPKI pin")
	}
}

func TestFetchRejectsServerError(t *testing.T) {
	srv, _ := mockserver.New([]byte(samplePayload))
	defer srv.Close()

	clientKey, _ := sign.GenerateKey()
	srv.RegisterClient(pub(clientKey))
	srv.RejectNext()

	cli := newClientFor(t, srv, false)

	_, err := transport.Fetch(context.Background(), cli, transport.FetchParams{
		Product:          "enclave",
		Build:            "backend",
		ClientVersion:    "0.0.0-dev",
		LicenseID:        "LCS-TEST",
		ClientSigningKey: clientKey,
		ServerVerifyKey:  pub(srv.ServerSigningKey),
	})
	var se *transport.ErrServerStatus
	if !errors.As(err, &se) || se.Status != 401 {
		t.Fatalf("got %v, want ErrServerStatus 401", err)
	}
}

func TestFetchRejectsWrongServerKey(t *testing.T) {
	srv, _ := mockserver.New([]byte(samplePayload))
	defer srv.Close()

	clientKey, _ := sign.GenerateKey()
	srv.RegisterClient(pub(clientKey))

	otherSrvKey, _ := sign.GenerateKey()

	cli := newClientFor(t, srv, false)

	_, err := transport.Fetch(context.Background(), cli, transport.FetchParams{
		Product:          "enclave",
		Build:            "backend",
		ClientVersion:    "0.0.0-dev",
		LicenseID:        "LCS-TEST",
		ClientSigningKey: clientKey,
		ServerVerifyKey:  pub(otherSrvKey), // wrong
	})
	if err == nil {
		t.Fatal("Fetch should fail when server pubkey doesn't match")
	}
}
