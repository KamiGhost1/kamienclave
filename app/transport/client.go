// Package transport contains the licence-server HTTP client and the
// high-level Fetch flow that turns a signed request into a decrypted
// JavaScript payload.
//
// Layering:
//
//   - Client is a thin wrapper over net/http with TLS 1.3 minimum and
//     SPKI pinning;
//   - Fetch composes Client with the crypto packages (sign, kex, aead)
//     and the proto canonicalisation to perform a complete handshake.
package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/KamiGhost1/kamienclave/proto"
	"github.com/KamiGhost1/kamienclave/transport/pin"
)

// Header names used by the protocol.
const (
	HeaderClientSig = "X-Enclave-Sig"
	HeaderServerSig = "X-Enclave-Server-Sig"

	defaultFetchPath = "/v1/fetch"

	maxResponseBytes = 8 << 20   // 8 MiB — well above any realistic obfuscated payload
	maxBlobBytes     = 512 << 20 // 512 MiB cap for out-of-band app bundles (режим B)
)

// ErrServerStatus wraps a non-2xx response so callers can distinguish
// transport-level failures from crypto/decode failures. The body is
// intentionally not exposed — see TECHNICAL.md §5.5.
type ErrServerStatus struct{ Status int }

func (e *ErrServerStatus) Error() string {
	return fmt.Sprintf("transport: server returned status %d", e.Status)
}

// Config configures a Client.
type Config struct {
	// ServerURL is the base URL of the licence server, e.g.
	// https://licence.enclave.example. Fetch appends /v1/fetch.
	ServerURL string

	// Pins is the set of acceptable SPKI fingerprints. Must be
	// non-empty in production; tests can disable pinning via the
	// AllowAnyServerCert option below.
	Pins *pin.Set

	// AllowAnyServerCert disables pinning AND chain validation. Must
	// stay false outside tests — guarded by build tag in a follow-up.
	AllowAnyServerCert bool

	// RootCAs is an optional explicit trust store. Nil means use the
	// system store. Tests inject the httptest server's CA pool here.
	RootCAs *tls.Config // pre-built tls.Config; only RootCAs/MinVersion fields are read

	// Timeout is the per-request hard timeout. Zero defaults to 30s.
	Timeout time.Duration

	// UserAgent override; defaults to "enclave/<version>".
	UserAgent string
}

// Client is a configured HTTP client that talks to the licence server.
type Client struct {
	cfg  Config
	http *http.Client
}

// NewClient builds a Client. The returned *http.Client uses TLS 1.3
// minimum and rejects any connection whose leaf certificate fails the
// configured SPKI pin set.
func NewClient(cfg Config) (*Client, error) {
	if cfg.ServerURL == "" {
		return nil, errors.New("transport: ServerURL is required")
	}
	if !cfg.AllowAnyServerCert && (cfg.Pins == nil) {
		return nil, errors.New("transport: Pins required when AllowAnyServerCert is false")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "enclave/0.0.0-dev"
	}

	tlsConf := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
	if cfg.RootCAs != nil {
		tlsConf.RootCAs = cfg.RootCAs.RootCAs
	}
	if cfg.AllowAnyServerCert {
		// Used only by tests. Pinning still runs if cfg.Pins != nil.
		tlsConf.InsecureSkipVerify = true
	}
	if cfg.Pins != nil {
		pinned := cfg.Pins
		tlsConf.VerifyConnection = func(cs tls.ConnectionState) error {
			return pinned.VerifyConnection(cs)
		}
	}

	tr := &http.Transport{
		TLSClientConfig:       tlsConf,
		ForceAttemptHTTP2:     true,
		DisableKeepAlives:     true, // each kamienclave invocation does one fetch
		MaxIdleConnsPerHost:   1,
		IdleConnTimeout:       5 * time.Second,
		ResponseHeaderTimeout: cfg.Timeout,
		TLSHandshakeTimeout:   10 * time.Second,
	}

	return &Client{
		cfg: cfg,
		http: &http.Client{
			Transport: tr,
			Timeout:   cfg.Timeout,
		},
	}, nil
}

// PostFetch sends a signed FetchRequest and returns the parsed
// FetchResponse plus the raw server-signature header (caller verifies
// it against the canonical response bytes).
func (c *Client) PostFetch(ctx context.Context, req *proto.FetchRequest, clientSig []byte) (*proto.FetchResponse, []byte, error) {
	body, err := proto.CanonicalRequest(req)
	if err != nil {
		return nil, nil, fmt.Errorf("transport: canonicalise: %w", err)
	}

	url := c.cfg.ServerURL + defaultFetchPath
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, nil, fmt.Errorf("transport: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", c.cfg.UserAgent)
	httpReq.Header.Set(HeaderClientSig, base64Std(clientSig))

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, nil, fmt.Errorf("transport: do: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode/100 != 2 {
		// Drain a small amount to allow connection reuse, then bail.
		_, _ = io.CopyN(io.Discard, resp.Body, 1<<10)
		return nil, nil, &ErrServerStatus{Status: resp.StatusCode}
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("transport: read body: %w", err)
	}
	if len(raw) > maxResponseBytes {
		return nil, nil, errors.New("transport: response exceeds size cap")
	}

	var fr proto.FetchResponse
	if err := json.Unmarshal(raw, &fr); err != nil {
		return nil, nil, fmt.Errorf("transport: decode response: %w", err)
	}

	sigB64 := resp.Header.Get(HeaderServerSig)
	if sigB64 == "" {
		return nil, nil, errors.New("transport: missing server signature header")
	}
	sig, err := decodeBase64(sigB64)
	if err != nil {
		return nil, nil, fmt.Errorf("transport: server sig decode: %w", err)
	}
	return &fr, sig, nil
}

// GetBlob downloads an out-of-band payload blob (режим B URL delivery)
// over the same pinned TLS connection. The blob is the self-protected
// .encpkg (AEAD under the per-license app key + server Ed25519 signature),
// so transport need only authenticate the channel and bound the size; the
// one-time token authorises the download.
func (c *Client) GetBlob(ctx context.Context, desc proto.BlobDescriptor) ([]byte, error) {
	if desc.Path == "" || desc.Token == "" {
		return nil, errors.New("transport: empty blob descriptor")
	}
	u := c.cfg.ServerURL + desc.Path + "?token=" + url.QueryEscape(desc.Token)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("transport: build blob request: %w", err)
	}
	httpReq.Header.Set("User-Agent", c.cfg.UserAgent)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("transport: blob do: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		_, _ = io.CopyN(io.Discard, resp.Body, 1<<10)
		return nil, &ErrServerStatus{Status: resp.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBlobBytes+1))
	if err != nil {
		return nil, fmt.Errorf("transport: read blob: %w", err)
	}
	if len(raw) > maxBlobBytes {
		return nil, errors.New("transport: blob exceeds size cap")
	}
	return raw, nil
}
