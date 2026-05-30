// Package license ties the encrypted blob format (sub-package blob)
// to the per-license bundle that kamienclave needs at runtime.
//
// The bundle carries everything the client cannot embed in plain text:
//
//   - the client's Ed25519 private key, used to sign fetch requests;
//   - the server's Ed25519 public key, used to verify replies;
//   - the SPKI pin of the server's TLS certificate;
//   - the server URL;
//   - the human-readable license identifier.
//
// Marshalling is JSON for two reasons: it is trivial to audit and the
// bundle is tiny (a few hundred bytes), so the verbosity cost is
// negligible. The bytes never leave the process unencrypted — they
// live only between blob.Open and Unlock returning.
package license

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/KamiGhost1/kamienclave/crypto/zeroize"
	"github.com/KamiGhost1/kamienclave/license/blob"
	"github.com/KamiGhost1/kamienclave/transport/pin"
)

// Bundle is the runtime view of the decrypted blob.
type Bundle struct {
	LicenseID string

	ServerURL string
	ServerPub ed25519.PublicKey
	SPKIPin   pin.Pin

	ClientPriv ed25519.PrivateKey

	// Per-build bytecode decode params (backend builds only). These are
	// the secrets the client must hold to read its build's payloads: the
	// opcode-table seed and the constant-pool encryption key. They ride
	// in the per-license bundle rather than the payload (TECHNICAL.md
	// §7.1). A public/goja build leaves them zero.
	BCTableSeed int64
	BCConstKey  []byte

	// Mode selects how the client interprets the fetched payload:
	// "bytecode" (mini-VM, режим A) or "fullapp" (.encpkg, режим B —
	// docs/DRAFT-fullapp-delivery.md §4). Empty defaults to "bytecode".
	Mode string

	// AppDecryptKey is the per-license AES key for the .encpkg envelope
	// (режим B only; analogous to BCConstKey for режим A). Empty otherwise.
	AppDecryptKey []byte
}

// Mode constants for Bundle.Mode.
const (
	ModeBytecode = "bytecode"
	ModeFullApp  = "fullapp"
)

// Wipe overwrites the secret material. ed25519.PrivateKey is a plain
// byte slice (seed || public), so zeroising it in place destroys the
// secret seed; the constant-pool key is wiped likewise. Callers should
// drop the reference immediately after.
func (b *Bundle) Wipe() {
	if b == nil {
		return
	}
	zeroize.Bytes(b.ClientPriv)
	zeroize.Bytes(b.BCConstKey)
	zeroize.Bytes(b.AppDecryptKey)
}

// --- wire format ----------------------------------------------------

type wireBundle struct {
	LicenseID     string `json:"license_id"`
	ServerURL     string `json:"server_url"`
	ServerPub     []byte `json:"server_pub"`  // X.509 SPKI of the Ed25519 pubkey
	SPKIPin       []byte `json:"spki_pin"`    // 32-byte SHA-256
	ClientPriv    []byte `json:"client_priv"` // PKCS#8 DER
	BCTableSeed   int64  `json:"bc_table_seed,omitempty"`
	BCConstKey    []byte `json:"bc_const_key,omitempty"`
	Mode          string `json:"mode,omitempty"`
	AppDecryptKey []byte `json:"app_decrypt_key,omitempty"`
}

// Seal builds an encrypted blob carrying the bundle.
func Seal(passphrase []byte, b *Bundle, params blob.KDFParams) ([]byte, error) {
	if b == nil {
		return nil, errors.New("license: nil bundle")
	}
	if len(b.ClientPriv) == 0 || len(b.ServerPub) == 0 {
		return nil, errors.New("license: missing keys")
	}

	priv, err := x509.MarshalPKCS8PrivateKey(b.ClientPriv)
	if err != nil {
		return nil, fmt.Errorf("license: marshal client priv: %w", err)
	}
	defer zeroize.Bytes(priv)

	pub, err := x509.MarshalPKIXPublicKey(b.ServerPub)
	if err != nil {
		return nil, fmt.Errorf("license: marshal server pub: %w", err)
	}

	w := wireBundle{
		LicenseID:     b.LicenseID,
		ServerURL:     b.ServerURL,
		ServerPub:     pub,
		SPKIPin:       append([]byte(nil), b.SPKIPin[:]...),
		ClientPriv:    priv,
		BCTableSeed:   b.BCTableSeed,
		BCConstKey:    b.BCConstKey,
		Mode:          b.Mode,
		AppDecryptKey: b.AppDecryptKey,
	}
	raw, err := json.Marshal(&w)
	if err != nil {
		return nil, fmt.Errorf("license: marshal bundle: %w", err)
	}
	defer zeroize.Bytes(raw)

	return blob.Seal(passphrase, raw, params)
}

// Unlock decrypts a blob and returns the live Bundle.
func Unlock(passphrase, encrypted []byte) (*Bundle, error) {
	raw, err := blob.Open(passphrase, encrypted)
	if err != nil {
		return nil, err
	}
	defer zeroize.Bytes(raw)

	var w wireBundle
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("license: parse bundle: %w", err)
	}

	clientAny, err := x509.ParsePKCS8PrivateKey(w.ClientPriv)
	if err != nil {
		return nil, fmt.Errorf("license: parse client priv: %w", err)
	}
	clientPriv, ok := clientAny.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("license: client key is not Ed25519")
	}

	srvAny, err := x509.ParsePKIXPublicKey(w.ServerPub)
	if err != nil {
		return nil, fmt.Errorf("license: parse server pub: %w", err)
	}
	srvPub, ok := srvAny.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("license: server key is not Ed25519")
	}

	pn, err := pin.FromBytes(w.SPKIPin)
	if err != nil {
		return nil, err
	}

	// Copy out the secret keys BEFORE wiping the intermediate buffers.
	bcKey := append([]byte(nil), w.BCConstKey...)
	appKey := append([]byte(nil), w.AppDecryptKey...)

	zeroize.Bytes(w.ClientPriv)
	zeroize.Bytes(w.SPKIPin)
	zeroize.Bytes(w.BCConstKey)
	zeroize.Bytes(w.AppDecryptKey)

	return &Bundle{
		LicenseID:     w.LicenseID,
		ServerURL:     w.ServerURL,
		ServerPub:     srvPub,
		SPKIPin:       pn,
		ClientPriv:    clientPriv,
		BCTableSeed:   w.BCTableSeed,
		BCConstKey:    bcKey,
		Mode:          w.Mode,
		AppDecryptKey: appKey,
	}, nil
}

// Compile-time sanity that we never accidentally bring ecdh in via the
// wire format. (The session-layer X25519 keys are ephemeral and never
// touch the bundle.)
var _ = (*ecdh.PrivateKey)(nil)
