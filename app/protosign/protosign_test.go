package protosign

import (
	"crypto/ed25519"
	"testing"

	"github.com/KamiGhost1/kamienclave/crypto/sign"
	"github.com/KamiGhost1/kamienclave/proto"
)

func pub(priv ed25519.PrivateKey) ed25519.PublicKey {
	return priv.Public().(ed25519.PublicKey)
}

func sampleRequest() *proto.FetchRequest {
	return &proto.FetchRequest{
		V:             1,
		Product:       "enclave",
		Build:         "backend",
		ClientVersion: "0.1.0",
		LicenseID:     "LCS-AAAA-BBBB",
		Nonce:         "Tk9OQ0VfRkFLRV9CQVNFNjQ=",
		TS:            1717075200,
		EphPub:        "RVBIX1BVQl9GQUtFX0JBU0U2NA==",
	}
}

func TestSignVerifyRequestRoundTrip(t *testing.T) {
	priv, err := sign.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	req := sampleRequest()
	sig, err := SignRequest(priv, req)
	if err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	if err := VerifyRequest(pub(priv), req, sig); err != nil {
		t.Fatalf("VerifyRequest: %v", err)
	}
}

func TestVerifyRequestDetectsTamper(t *testing.T) {
	priv, _ := sign.GenerateKey()
	req := sampleRequest()
	sig, _ := SignRequest(priv, req)

	req.LicenseID = "LCS-EVIL"
	if err := VerifyRequest(pub(priv), req, sig); err == nil {
		t.Fatal("verify must fail after field mutation")
	}
}

func TestSignVerifyResponseRoundTrip(t *testing.T) {
	priv, _ := sign.GenerateKey()
	resp := &proto.FetchResponse{V: 1, EphPub: "a", Salt: "b", Nonce: "c", CT: "d"}
	sig, err := SignResponse(priv, resp)
	if err != nil {
		t.Fatalf("SignResponse: %v", err)
	}
	if err := VerifyResponse(pub(priv), resp, sig); err != nil {
		t.Fatalf("VerifyResponse: %v", err)
	}
}
