package pin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func issueSelfSigned(t *testing.T) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return cert
}

func TestComputeStable(t *testing.T) {
	cert := issueSelfSigned(t)
	a := Compute(cert)
	b := Compute(cert)
	if a != b {
		t.Fatal("Compute non-deterministic")
	}
}

func TestSetVerifyMatchAndMiss(t *testing.T) {
	c1 := issueSelfSigned(t)
	c2 := issueSelfSigned(t)

	set := NewSet(Compute(c1))
	if err := set.Verify(c1); err != nil {
		t.Fatalf("Verify matching: %v", err)
	}
	if err := set.Verify(c2); err == nil {
		t.Fatal("Verify other cert should fail")
	}
}

func TestSetEmptyRejects(t *testing.T) {
	c := issueSelfSigned(t)
	set := NewSet()
	if err := set.Verify(c); err == nil {
		t.Fatal("empty set must reject everything")
	}
}

func TestPinHexBase64RoundTrip(t *testing.T) {
	c := issueSelfSigned(t)
	p := Compute(c)
	hp, err := FromHex(p.Hex())
	if err != nil {
		t.Fatalf("FromHex: %v", err)
	}
	bp, err := FromBase64(p.Base64())
	if err != nil {
		t.Fatalf("FromBase64: %v", err)
	}
	if hp != p || bp != p {
		t.Fatal("round-trip differs")
	}
}
