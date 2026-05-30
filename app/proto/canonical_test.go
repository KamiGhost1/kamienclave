package proto

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func sampleRequest() *FetchRequest {
	return &FetchRequest{
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

func TestCanonicalRequestStability(t *testing.T) {
	r := sampleRequest()
	a, err := CanonicalRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	b, err := CanonicalRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("canonical not deterministic: %q vs %q", a, b)
	}
}

func TestCanonicalRequestSortedKeys(t *testing.T) {
	out, err := CanonicalRequest(sampleRequest())
	if err != nil {
		t.Fatal(err)
	}

	// 1. parses as valid JSON
	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}

	// 2. keys appear in lex order in the raw bytes
	gotOrder := keyOrderInBytes(t, out)
	want := append([]string(nil), gotOrder...)
	sort.Strings(want)
	if !reflect.DeepEqual(gotOrder, want) {
		t.Fatalf("keys not sorted: got %v want %v", gotOrder, want)
	}

	// 3. no whitespace
	if strings.ContainsAny(string(out), " \t\n\r") {
		t.Fatalf("canonical form contains whitespace: %q", out)
	}
}

func TestCanonicalRequestRoundTrip(t *testing.T) {
	r := sampleRequest()
	out, err := CanonicalRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	var got FetchRequest
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(*r, got) {
		t.Fatalf("round-trip differs:\n got: %+v\nwant: %+v", got, *r)
	}
}

func TestCanonicalRequestEscaping(t *testing.T) {
	r := sampleRequest()
	r.LicenseID = `quote " backslash \ unicode Ω`
	out, err := CanonicalRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	var got FetchRequest
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("escape round-trip failed: %v", err)
	}
	if got.LicenseID != r.LicenseID {
		t.Fatalf("escape decode mismatch: %q vs %q", got.LicenseID, r.LicenseID)
	}
}

func TestCanonicalRequestRejectsNil(t *testing.T) {
	if _, err := CanonicalRequest(nil); err == nil {
		t.Fatal("expected error for nil request")
	}
}

func TestCanonicalResponse(t *testing.T) {
	resp := &FetchResponse{
		V:      1,
		EphPub: "AAAA",
		Salt:   "BBBB",
		Nonce:  "CCCC",
		CT:     "DDDD",
	}
	out, err := CanonicalResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	gotOrder := keyOrderInBytes(t, out)
	want := []string{"ct", "delivery", "eph_pub", "nonce", "salt", "v"}
	if !reflect.DeepEqual(gotOrder, want) {
		t.Fatalf("response keys order: got %v want %v", gotOrder, want)
	}
}

// keyOrderInBytes extracts top-level JSON keys in their byte order. It
// relies on the fact that our canonical encoder never emits whitespace
// or nested objects.
func keyOrderInBytes(t *testing.T, raw []byte) []string {
	t.Helper()
	s := string(raw)
	if !strings.HasPrefix(s, "{") || !strings.HasSuffix(s, "}") {
		t.Fatalf("not a top-level object: %q", s)
	}
	s = strings.TrimSuffix(strings.TrimPrefix(s, "{"), "}")
	var keys []string
	for _, part := range splitTopLevel(s) {
		i := strings.Index(part, `":`)
		if i < 0 {
			t.Fatalf("bad pair: %q", part)
		}
		k := strings.TrimPrefix(part[:i], `"`)
		keys = append(keys, k)
	}
	return keys
}

// splitTopLevel splits at commas that aren't inside a JSON string.
// Sufficient for our flat canonical output.
func splitTopLevel(s string) []string {
	var out []string
	depth := 0
	inStr := false
	esc := false
	start := 0
	for i, c := range s {
		switch {
		case esc:
			esc = false
		case c == '\\' && inStr:
			esc = true
		case c == '"':
			inStr = !inStr
		case !inStr && (c == '{' || c == '['):
			depth++
		case !inStr && (c == '}' || c == ']'):
			depth--
		case !inStr && depth == 0 && c == ',':
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
