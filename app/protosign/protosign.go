// Package protosign is the client/server glue that signs and verifies
// protocol DTOs. It deliberately lives OUTSIDE the proto package so that
// proto stays a pure, dependency-free wire contract (DTOs + canonical
// encoding) ready to be extracted into the shared kamienclave-proto module;
// the Ed25519 signing dependency stays on this side of that boundary.
package protosign

import (
	"crypto/ed25519"

	"github.com/KamiGhost1/kamienclave/crypto/sign"
	"github.com/KamiGhost1/kamienclave/proto"
)

// SignRequest returns the Ed25519 signature over the canonical byte
// representation of req.
func SignRequest(priv ed25519.PrivateKey, req *proto.FetchRequest) ([]byte, error) {
	canon, err := proto.CanonicalRequest(req)
	if err != nil {
		return nil, err
	}
	return sign.Sign(priv, canon)
}

// VerifyRequest checks sig against the canonical representation of req.
func VerifyRequest(pub ed25519.PublicKey, req *proto.FetchRequest, sig []byte) error {
	canon, err := proto.CanonicalRequest(req)
	if err != nil {
		return err
	}
	return sign.Verify(pub, canon, sig)
}

// SignResponse / VerifyResponse mirror the request helpers for the
// server-signed reply.
func SignResponse(priv ed25519.PrivateKey, resp *proto.FetchResponse) ([]byte, error) {
	canon, err := proto.CanonicalResponse(resp)
	if err != nil {
		return nil, err
	}
	return sign.Sign(priv, canon)
}

func VerifyResponse(pub ed25519.PublicKey, resp *proto.FetchResponse, sig []byte) error {
	canon, err := proto.CanonicalResponse(resp)
	if err != nil {
		return err
	}
	return sign.Verify(pub, canon, sig)
}
