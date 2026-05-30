package sign

import (
	"crypto/ed25519"
	"testing"
)

func pub(priv ed25519.PrivateKey) ed25519.PublicKey {
	return priv.Public().(ed25519.PublicKey)
}

func TestSignVerifyRoundTrip(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	msg := []byte("enclave handshake payload v1")
	sig, err := Sign(priv, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != SignatureSize {
		t.Fatalf("sig len = %d, want %d", len(sig), SignatureSize)
	}
	if err := Verify(pub(priv), msg, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyRejectsTampered(t *testing.T) {
	priv, _ := GenerateKey()
	msg := []byte("hello")
	sig, _ := Sign(priv, msg)

	tampered := append([]byte(nil), msg...)
	tampered[0] ^= 0x01
	if err := Verify(pub(priv), tampered, sig); err == nil {
		t.Fatal("verify should fail on tampered message")
	}

	badsig := append([]byte(nil), sig...)
	badsig[0] ^= 0x01
	if err := Verify(pub(priv), msg, badsig); err == nil {
		t.Fatal("verify should fail on tampered signature")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	priv, _ := GenerateKey()
	other, _ := GenerateKey()
	sig, _ := Sign(priv, []byte("x"))
	if err := Verify(pub(other), []byte("x"), sig); err == nil {
		t.Fatal("verify should fail for wrong key")
	}
}

func TestSignRejectsMalformedKey(t *testing.T) {
	short := ed25519.PrivateKey(make([]byte, 10))
	if _, err := Sign(short, []byte("x")); err != ErrWrongKey {
		t.Fatalf("Sign on short key = %v, want ErrWrongKey", err)
	}
	if err := Verify(ed25519.PublicKey(make([]byte, 10)), []byte("x"), make([]byte, SignatureSize)); err != ErrWrongKey {
		t.Fatalf("Verify on short key = %v, want ErrWrongKey", err)
	}
}

func TestVerifyRejectsBadLength(t *testing.T) {
	priv, _ := GenerateKey()
	if err := Verify(pub(priv), []byte("x"), []byte{1, 2, 3}); err != ErrInvalidSignature {
		t.Fatalf("got %v, want ErrInvalidSignature", err)
	}
}
