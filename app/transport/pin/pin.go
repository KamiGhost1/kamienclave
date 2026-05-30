// Package pin implements SubjectPublicKeyInfo (SPKI) certificate
// pinning for TLS handshakes. The pin is the SHA-256 of the leaf
// certificate's DER-encoded SPKI — the same value HPKP and most
// pinning specifications agree on.
//
// We pin the leaf rather than an intermediate so that compromise of a
// public CA in the user's trust store cannot be used to forge a
// connection to the kamienclave server.
package pin

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// Size is the length of an SPKI pin in bytes.
const Size = sha256.Size

// ErrNoMatch is returned when none of the configured pins matches the
// presented leaf certificate's SPKI digest.
var ErrNoMatch = errors.New("pin: no matching SPKI pin")

// Pin is a 32-byte SPKI SHA-256 fingerprint.
type Pin [Size]byte

// FromBytes builds a Pin from a raw 32-byte slice.
func FromBytes(b []byte) (Pin, error) {
	var p Pin
	if len(b) != Size {
		return p, fmt.Errorf("pin: want %d bytes, got %d", Size, len(b))
	}
	copy(p[:], b)
	return p, nil
}

// FromHex parses a hex-encoded SPKI fingerprint.
func FromHex(s string) (Pin, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return Pin{}, fmt.Errorf("pin: hex decode: %w", err)
	}
	return FromBytes(b)
}

// FromBase64 parses a standard base64-encoded SPKI fingerprint.
func FromBase64(s string) (Pin, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return Pin{}, fmt.Errorf("pin: base64 decode: %w", err)
	}
	return FromBytes(b)
}

func (p Pin) Hex() string    { return hex.EncodeToString(p[:]) }
func (p Pin) Base64() string { return base64.StdEncoding.EncodeToString(p[:]) }

// Compute returns the SPKI fingerprint of cert.
func Compute(cert *x509.Certificate) Pin {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return Pin(sum)
}

// Set is an ordered, immutable collection of acceptable pins. Lookup
// is linear — pin rotations rarely exceed a handful of entries.
type Set struct {
	pins []Pin
}

// NewSet builds a Set; an empty set fails Verify unconditionally
// (callers should treat that as a configuration bug).
func NewSet(pins ...Pin) *Set { return &Set{pins: append([]Pin(nil), pins...)} }

// Verify reports nil if cert's SPKI matches one of the configured
// pins, otherwise ErrNoMatch.
func (s *Set) Verify(cert *x509.Certificate) error {
	if s == nil || len(s.pins) == 0 {
		return ErrNoMatch
	}
	got := Compute(cert)
	for _, want := range s.pins {
		if got == want {
			return nil
		}
	}
	return ErrNoMatch
}

// VerifyConnection is suitable for tls.Config.VerifyConnection. It
// inspects the leaf certificate after the TLS stack has finished
// chain validation and refuses the connection on a pin mismatch.
func (s *Set) VerifyConnection(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("pin: peer presented no certificate")
	}
	return s.Verify(cs.PeerCertificates[0])
}
