// Package proto holds the wire-format DTOs shared between kamienclave-client
// and kamienclave-server. Once the protocol stabilises this package will be
// extracted into the standalone `kamienclave-proto` module referenced from
// TECHNICAL.md §1.
package proto

const Version = 1

// FetchRequest is the canonical payload of POST /v1/fetch. It is
// serialised via JCS (RFC 8785) for signing.
type FetchRequest struct {
	V             int    `json:"v"`
	Product       string `json:"product"`
	Build         string `json:"build"` // "public" | "backend"
	ClientVersion string `json:"client_version"`
	LicenseID     string `json:"license_id"`
	Nonce         string `json:"nonce"`   // base64, 32 random bytes
	TS            int64  `json:"ts"`      // unix seconds
	EphPub        string `json:"eph_pub"` // base64 X25519 client ephemeral pubkey
}

// FetchResponse is the server reply: AEAD-encrypted payload plus the
// material needed to derive the session key.
//
// Draft 0.2: the old tag_hash (SHA-256 of plaintext) was removed — GCM's
// tag already guarantees integrity, and shipping a hash of the plaintext
// is a confirmation oracle for guessable payloads. The GCM nonce is now
// random per response rather than a hardcoded zero.
type FetchResponse struct {
	V      int    `json:"v"`
	EphPub string `json:"eph_pub"` // base64 X25519 server ephemeral pubkey
	Salt   string `json:"salt"`    // base64 16-byte HKDF salt
	Nonce  string `json:"nonce"`   // base64 12-byte GCM nonce
	CT     string `json:"ct"`      // base64 AES-256-GCM ciphertext

	// Delivery selects how CT is interpreted (signed via canonical form):
	//   ""    / "inline" — CT decrypts to the payload bytes directly
	//                      (режим A bytecode, small режим B).
	//   "url"            — CT decrypts to a JSON BlobDescriptor; the
	//                      client GETs the (self-protected) .encpkg blob
	//                      out of band. Used for large fullapp bundles.
	Delivery string `json:"delivery,omitempty"`
}

// Delivery modes for FetchResponse.Delivery.
const (
	DeliveryInline = "inline"
	DeliveryURL    = "url"
)

// BlobDescriptor is the (encrypted, inside CT) pointer to an out-of-band
// blob download. The blob itself is the self-protected .encpkg, so the
// token only needs to authorise the download, not protect the bytes.
type BlobDescriptor struct {
	Path  string `json:"path"`  // server path, e.g. "/v1/blob"
	Token string `json:"token"` // one-time, TTL-bound download token
	Size  int64  `json:"size"`  // expected blob size in bytes (advisory)
}
