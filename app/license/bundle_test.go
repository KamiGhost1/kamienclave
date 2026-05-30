package license

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"testing"

	"github.com/KamiGhost1/kamienclave/crypto/sign"
	"github.com/KamiGhost1/kamienclave/license/blob"
	"github.com/KamiGhost1/kamienclave/transport/pin"
)

func fastParams() blob.KDFParams {
	return blob.KDFParams{Time: 1, MemoryKiB: 8 * 1024, Parallelism: 1}
}

func sampleBundle(t *testing.T) *Bundle {
	t.Helper()
	cliKey, err := sign.GenerateKey()
	if err != nil {
		t.Fatalf("client gen: %v", err)
	}
	srvKey, err := sign.GenerateKey()
	if err != nil {
		t.Fatalf("server gen: %v", err)
	}
	return &Bundle{
		LicenseID:  "LCS-ABC123",
		ServerURL:  "https://licence.enclave.example",
		ServerPub:  srvKey.Public().(ed25519.PublicKey),
		SPKIPin:    pin.Pin{1, 2, 3, 4},
		ClientPriv: cliKey,
	}
}

func TestSealUnlockRoundTrip(t *testing.T) {
	b := sampleBundle(t)
	pass := []byte("hunter2")

	enc, err := Seal(pass, b, fastParams())
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	got, err := Unlock(pass, enc)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	if got.LicenseID != b.LicenseID {
		t.Errorf("license id: got %q want %q", got.LicenseID, b.LicenseID)
	}
	if got.ServerURL != b.ServerURL {
		t.Errorf("server url: got %q want %q", got.ServerURL, b.ServerURL)
	}
	if got.SPKIPin != b.SPKIPin {
		t.Errorf("pin differs")
	}

	// Round-trip the keys through marshalling to compare.
	if origPub, _ := x509.MarshalPKIXPublicKey(b.ServerPub); true {
		gotPub, _ := x509.MarshalPKIXPublicKey(got.ServerPub)
		if string(origPub) != string(gotPub) {
			t.Errorf("server pub differs")
		}
	}
	if origPriv, _ := x509.MarshalPKCS8PrivateKey(b.ClientPriv); true {
		gotPriv, _ := x509.MarshalPKCS8PrivateKey(got.ClientPriv)
		if string(origPriv) != string(gotPriv) {
			t.Errorf("client priv differs")
		}
	}
}

func TestSealUnlockRoundTripsBytecodeParams(t *testing.T) {
	b := sampleBundle(t)
	b.BCTableSeed = 0x0BADC0DE
	b.BCConstKey = bytes.Repeat([]byte{0x42}, 32)
	pass := []byte("pw")

	enc, err := Seal(pass, b, fastParams())
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := Unlock(pass, enc)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if got.BCTableSeed != b.BCTableSeed {
		t.Errorf("table seed: got %#x want %#x", got.BCTableSeed, b.BCTableSeed)
	}
	if !bytes.Equal(got.BCConstKey, bytes.Repeat([]byte{0x42}, 32)) {
		t.Errorf("const key not round-tripped: %x", got.BCConstKey)
	}
	got.Wipe()
	for _, v := range got.BCConstKey {
		if v != 0 {
			t.Fatal("BCConstKey not wiped")
		}
	}
}

func TestUnlockRejectsWrongPassphrase(t *testing.T) {
	b := sampleBundle(t)
	enc, _ := Seal([]byte("right"), b, fastParams())
	if _, err := Unlock([]byte("wrong"), enc); err == nil {
		t.Fatal("Unlock should fail with wrong passphrase")
	}
}

func TestWipeZeroesPrivate(t *testing.T) {
	b := sampleBundle(t)
	b.Wipe()
	for i, v := range b.ClientPriv {
		if v != 0 {
			t.Fatalf("ClientPriv[%d] = %d, not zeroed", i, v)
		}
	}
}
