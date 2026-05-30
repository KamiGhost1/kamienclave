// Package mockserver is a httptest-based stand-in for the licence
// server. It implements just enough of the protocol to exercise the
// client end-to-end: request signature verification, AEAD-encrypted
// reply, server signature, nonce + ts checks.
//
// Intended for tests only.
package mockserver

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"github.com/KamiGhost1/kamienclave/crypto/aead"
	"github.com/KamiGhost1/kamienclave/crypto/kex"
	"github.com/KamiGhost1/kamienclave/crypto/sign"
	"github.com/KamiGhost1/kamienclave/proto"
	"github.com/KamiGhost1/kamienclave/protosign"
	"github.com/KamiGhost1/kamienclave/transport"
)

// Server is the test double.
type Server struct {
	HTTP *httptest.Server

	// ServerSigningKey is the private Ed25519 key the mock uses to sign
	// its replies. Expose the public half to the client under test.
	ServerSigningKey ed25519.PrivateKey

	// ClientVerifyKey is the public Ed25519 key used to verify incoming
	// requests. Populated by RegisterClient.
	ClientVerifyKey ed25519.PublicKey

	// Payload is the plaintext JavaScript the server will hand out.
	Payload []byte

	// MaxClockSkew bounds |now - request.ts|; 0 disables the check.
	MaxClockSkew time.Duration

	mu          sync.Mutex
	seenNonces  map[string]struct{}
	rejectNext  bool // for tests that want to see a 401 path
	rejectCount int
}

// New starts a TLS test server pre-configured with a fresh signing
// keypair. The caller registers an authorised client via
// RegisterClient and sets Payload before driving the client under test.
func New(payload []byte) (*Server, error) {
	priv, err := sign.GenerateKey()
	if err != nil {
		return nil, err
	}
	s := &Server{
		ServerSigningKey: priv,
		Payload:          append([]byte(nil), payload...),
		MaxClockSkew:     60 * time.Second,
		seenNonces:       map[string]struct{}{},
	}
	s.HTTP = httptest.NewTLSServer(http.HandlerFunc(s.handle))
	return s, nil
}

func (s *Server) Close() {
	if s.HTTP != nil {
		s.HTTP.Close()
	}
}

// RegisterClient stores the public key that incoming requests will be
// verified against.
func (s *Server) RegisterClient(pub ed25519.PublicKey) {
	s.mu.Lock()
	s.ClientVerifyKey = pub
	s.mu.Unlock()
}

// RejectNext makes the next request fail with 401 — used to exercise
// the client's error path.
func (s *Server) RejectNext() {
	s.mu.Lock()
	s.rejectNext = true
	s.mu.Unlock()
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/v1/fetch" {
		http.Error(w, "", http.StatusNotFound)
		return
	}

	s.mu.Lock()
	if s.rejectNext {
		s.rejectNext = false
		s.rejectCount++
		s.mu.Unlock()
		http.Error(w, "", http.StatusUnauthorized)
		return
	}
	clientPub := s.ClientVerifyKey
	s.mu.Unlock()

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	var req proto.FetchRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	sigHdr := r.Header.Get(transport.HeaderClientSig)
	sig, err := base64.StdEncoding.DecodeString(sigHdr)
	if err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	if clientPub == nil {
		http.Error(w, "", http.StatusUnauthorized)
		return
	}
	if err := protosign.VerifyRequest(clientPub, &req, sig); err != nil {
		http.Error(w, "", http.StatusUnauthorized)
		return
	}

	if err := s.checkFreshness(&req); err != nil {
		http.Error(w, "", http.StatusUnauthorized)
		return
	}

	// Derive session key with our own ephemeral pair.
	srvEph, err := kex.Generate()
	if err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	clientPubBytes, err := base64.StdEncoding.DecodeString(req.EphPub)
	if err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	clientEph, err := kex.ParsePublic(clientPubBytes)
	if err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	key, err := kex.Derive(srvEph, clientEph, salt)
	if err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	nonce := make([]byte, aead.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	ct, err := aead.SealWithNonce(key, nonce, s.Payload, nil)
	if err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	resp := &proto.FetchResponse{
		V:      proto.Version,
		EphPub: base64.StdEncoding.EncodeToString(srvEph.PublicKey().Bytes()),
		Salt:   base64.StdEncoding.EncodeToString(salt),
		Nonce:  base64.StdEncoding.EncodeToString(nonce),
		CT:     base64.StdEncoding.EncodeToString(ct),
	}

	respSig, err := protosign.SignResponse(s.ServerSigningKey, resp)
	if err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(transport.HeaderServerSig, base64.StdEncoding.EncodeToString(respSig))

	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) checkFreshness(req *proto.FetchRequest) error {
	if s.MaxClockSkew > 0 {
		dt := time.Since(time.Unix(req.TS, 0))
		if dt < -s.MaxClockSkew || dt > s.MaxClockSkew {
			return errors.New("stale ts")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, seen := s.seenNonces[req.Nonce]; seen {
		return errors.New("nonce replay")
	}
	s.seenNonces[req.Nonce] = struct{}{}
	return nil
}

// MustParseClientEphPub is a small helper kept exported so the test
// can sanity-check the request shape if needed.
func MustParseClientEphPub(b64 string) (*ecdh.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	return kex.ParsePublic(raw)
}
