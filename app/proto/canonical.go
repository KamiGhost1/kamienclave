package proto

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// CanonicalRequest produces the deterministic byte representation of a
// FetchRequest used for Ed25519 signing. The encoding rules are a
// hand-coded subset of RFC 8785 (JCS), sufficient for our flat DTO:
//
//   - keys appear in lexicographic byte order;
//   - no whitespace;
//   - strings are JSON-encoded with HTML escaping disabled (RFC 8259);
//   - integers are written as plain decimal digits (no exponent, no
//     leading zero, no sign for positive values).
//
// We intentionally avoid runtime reflection so the wire format is easy
// to mirror in the server implementation and to audit by inspection.
func CanonicalRequest(r *FetchRequest) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("proto: nil request")
	}

	var b bytes.Buffer
	b.WriteByte('{')

	if err := writeStringField(&b, "build", r.Build); err != nil {
		return nil, err
	}
	b.WriteByte(',')
	if err := writeStringField(&b, "client_version", r.ClientVersion); err != nil {
		return nil, err
	}
	b.WriteByte(',')
	if err := writeStringField(&b, "eph_pub", r.EphPub); err != nil {
		return nil, err
	}
	b.WriteByte(',')
	if err := writeStringField(&b, "license_id", r.LicenseID); err != nil {
		return nil, err
	}
	b.WriteByte(',')
	if err := writeStringField(&b, "nonce", r.Nonce); err != nil {
		return nil, err
	}
	b.WriteByte(',')
	if err := writeStringField(&b, "product", r.Product); err != nil {
		return nil, err
	}
	b.WriteByte(',')
	fmt.Fprintf(&b, `"ts":%d`, r.TS)
	b.WriteByte(',')
	fmt.Fprintf(&b, `"v":%d`, r.V)

	b.WriteByte('}')
	return b.Bytes(), nil
}

// CanonicalResponse mirrors CanonicalRequest for FetchResponse so the
// server can sign its reply using the same encoding rules.
func CanonicalResponse(r *FetchResponse) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("proto: nil response")
	}

	var b bytes.Buffer
	b.WriteByte('{')

	if err := writeStringField(&b, "ct", r.CT); err != nil {
		return nil, err
	}
	b.WriteByte(',')
	if err := writeStringField(&b, "delivery", r.Delivery); err != nil {
		return nil, err
	}
	b.WriteByte(',')
	if err := writeStringField(&b, "eph_pub", r.EphPub); err != nil {
		return nil, err
	}
	b.WriteByte(',')
	if err := writeStringField(&b, "nonce", r.Nonce); err != nil {
		return nil, err
	}
	b.WriteByte(',')
	if err := writeStringField(&b, "salt", r.Salt); err != nil {
		return nil, err
	}
	b.WriteByte(',')
	fmt.Fprintf(&b, `"v":%d`, r.V)

	b.WriteByte('}')
	return b.Bytes(), nil
}

func writeStringField(b *bytes.Buffer, key, val string) error {
	kb, err := jsonString(key)
	if err != nil {
		return err
	}
	vb, err := jsonString(val)
	if err != nil {
		return err
	}
	b.Write(kb)
	b.WriteByte(':')
	b.Write(vb)
	return nil
}

func jsonString(s string) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	// json.Encoder.Encode appends a trailing '\n' that we don't want.
	out := buf.Bytes()
	return out[:len(out)-1], nil
}
