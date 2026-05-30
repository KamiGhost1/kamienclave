package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/KamiGhost1/kamienclave/crypto/aead"
	"github.com/KamiGhost1/kamienclave/crypto/kex"
	"github.com/KamiGhost1/kamienclave/crypto/zeroize"
	"github.com/KamiGhost1/kamienclave/proto"
	"github.com/KamiGhost1/kamienclave/protosign"
)

// FetchParams gathers everything Fetch needs at the application layer.
type FetchParams struct {
	Product       string
	Build         string // "public" | "backend"
	ClientVersion string
	LicenseID     string

	// ClientSigningKey is the private Ed25519 key used to authenticate
	// the request. It is wiped from the caller's struct after use.
	ClientSigningKey ed25519.PrivateKey

	// ServerVerifyKey is the pinned public key used to verify the
	// signature attached to the server's reply.
	ServerVerifyKey ed25519.PublicKey
}

// Fetch runs a complete handshake against the licence server and
// returns the decrypted JavaScript payload. The returned slice is the
// only place the plaintext lives; callers are expected to wipe it via
// zeroize.Bytes as soon as the runtime has compiled it.
func Fetch(ctx context.Context, c *Client, p FetchParams) ([]byte, error) {
	if c == nil {
		return nil, errors.New("transport: nil client")
	}
	if len(p.ClientSigningKey) == 0 || len(p.ServerVerifyKey) == 0 {
		return nil, errors.New("transport: missing keys")
	}

	// 1. Build request DTO with fresh nonce + ephemeral keypair.
	eph, err := kex.Generate()
	if err != nil {
		return nil, fmt.Errorf("transport: kex: %w", err)
	}

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("transport: nonce: %w", err)
	}

	req := &proto.FetchRequest{
		V:             proto.Version,
		Product:       p.Product,
		Build:         p.Build,
		ClientVersion: p.ClientVersion,
		LicenseID:     p.LicenseID,
		Nonce:         base64.StdEncoding.EncodeToString(nonce),
		TS:            time.Now().Unix(),
		EphPub:        base64.StdEncoding.EncodeToString(eph.PublicKey().Bytes()),
	}

	// 2. Sign canonical form.
	sig, err := protosign.SignRequest(p.ClientSigningKey, req)
	if err != nil {
		return nil, fmt.Errorf("transport: sign: %w", err)
	}

	// 3. Send.
	resp, serverSig, err := c.PostFetch(ctx, req, sig)
	if err != nil {
		return nil, err
	}

	// 4. Verify server signature over canonical response.
	if err := protosign.VerifyResponse(p.ServerVerifyKey, resp, serverSig); err != nil {
		return nil, fmt.Errorf("transport: server signature invalid: %w", err)
	}

	// 5. Derive session key from ECDH(eph_priv, server_eph_pub) with the
	// salt the server chose.
	srvPubBytes, err := base64.StdEncoding.DecodeString(resp.EphPub)
	if err != nil {
		return nil, fmt.Errorf("transport: server eph_pub decode: %w", err)
	}
	srvPub, err := kex.ParsePublic(srvPubBytes)
	if err != nil {
		return nil, fmt.Errorf("transport: server eph_pub parse: %w", err)
	}
	salt, err := base64.StdEncoding.DecodeString(resp.Salt)
	if err != nil {
		return nil, fmt.Errorf("transport: salt decode: %w", err)
	}

	key, err := kex.Derive(eph, srvPub, salt)
	if err != nil {
		return nil, fmt.Errorf("transport: derive: %w", err)
	}
	defer zeroize.Bytes(key)

	// 6. AEAD open with the server-supplied random nonce. GCM's tag
	// provides integrity; there is no separate plaintext hash to check.
	respNonce, err := base64.StdEncoding.DecodeString(resp.Nonce)
	if err != nil {
		return nil, fmt.Errorf("transport: nonce decode: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(resp.CT)
	if err != nil {
		return nil, fmt.Errorf("transport: ct decode: %w", err)
	}
	plain, err := aead.OpenWithNonce(key, respNonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("transport: aead open: %w", err)
	}

	// 7. Delivery: inline returns the decrypted bytes directly; "url"
	// means `plain` is a BlobDescriptor and the real (self-protected)
	// payload must be fetched out of band. The indirection is invisible
	// to callers — Fetch returns the final payload bytes either way.
	if resp.Delivery == proto.DeliveryURL {
		defer zeroize.Bytes(plain)
		var desc proto.BlobDescriptor
		if err := json.Unmarshal(plain, &desc); err != nil {
			return nil, fmt.Errorf("transport: blob descriptor: %w", err)
		}
		return c.GetBlob(ctx, desc)
	}
	return plain, nil
}
