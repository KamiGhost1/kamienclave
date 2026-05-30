package bytecode

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func encKey(b byte) []byte {
	k := make([]byte, ConstKeySize)
	for i := range k {
		k[i] = b
	}
	return k
}

func secretProgram(t *testing.T) *Program {
	t.Helper()
	a := NewAssembler()
	a.PushString("secret-sauce")
	a.PushNumber(1337)
	a.Op(OpAdd) // "secret-sauce1337"
	a.Op(OpReturn)
	p, err := a.Build()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEncryptedRoundTrip(t *testing.T) {
	p := secretProgram(t)
	tbl := NewTableFromSeed(99)
	key := encKey(0xAB)

	raw, err := EncodeEncrypted(p, tbl, key)
	if err != nil {
		t.Fatalf("EncodeEncrypted: %v", err)
	}
	if bytes.Contains(raw, []byte("secret-sauce")) {
		t.Fatal("plaintext constant leaked into encrypted payload")
	}

	got, err := DecodeEncrypted(raw, tbl, key)
	if err != nil {
		t.Fatalf("DecodeEncrypted: %v", err)
	}
	v, err := got.Run(context.Background(), nil, Limits{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if v.Str() != "secret-sauce1337" {
		t.Fatalf("got %q, want secret-sauce1337", v.Str())
	}
}

func TestEncryptedWrongKeyFails(t *testing.T) {
	p := secretProgram(t)
	tbl := NewTableFromSeed(99)
	raw, err := EncodeEncrypted(p, tbl, encKey(0x01))
	if err != nil {
		t.Fatal(err)
	}
	// A wrong key yields garbage for the length-prefixed string constant,
	// which the parser rejects. (ChaCha20 is unauthenticated, so this is
	// detection-by-structure, not a MAC — the AEAD transport layer and
	// the server signature provide the real integrity guarantee.)
	if _, err := DecodeEncrypted(raw, tbl, encKey(0x02)); err == nil {
		t.Fatal("decode with wrong key should fail")
	}
}

func TestDecodeRejectsEncryptedWithoutKey(t *testing.T) {
	p := secretProgram(t)
	tbl := NewTableFromSeed(99)
	raw, _ := EncodeEncrypted(p, tbl, encKey(0x05))
	if _, err := Decode(raw, tbl); !errors.Is(err, ErrKeyRequired) {
		t.Fatalf("got %v, want ErrKeyRequired", err)
	}
}

func TestDecodeEncryptedAcceptsClearProgram(t *testing.T) {
	p := secretProgram(t)
	tbl := NewTableFromSeed(99)
	raw, _ := Encode(p, tbl) // clear pool
	got, err := DecodeEncrypted(raw, tbl, encKey(0x07))
	if err != nil {
		t.Fatalf("DecodeEncrypted on clear program: %v", err)
	}
	if v, _ := got.Run(context.Background(), nil, Limits{}); v.Str() != "secret-sauce1337" {
		t.Fatalf("clear-program run = %q", v.Str())
	}
}

func TestEncodeEncryptedRejectsBadKeySize(t *testing.T) {
	p := secretProgram(t)
	if _, err := EncodeEncrypted(p, IdentityTable(), make([]byte, 10)); !errors.Is(err, ErrKeySize) {
		t.Fatalf("got %v, want ErrKeySize", err)
	}
}
