package encpkg

import (
	"crypto/ed25519"
	"testing"

	"github.com/KamiGhost1/kamienclave/crypto/aead"
	"github.com/KamiGhost1/kamienclave/crypto/sign"
)

// FuzzOpen feeds arbitrary bytes to the .encpkg parser. The package
// arrives over the network, so Open must never panic or read out of
// bounds on malformed input — only return an error or a valid result.
func FuzzOpen(f *testing.F) {
	key := make([]byte, aead.KeySize)
	for i := range key {
		key[i] = byte(i * 7)
	}
	pub, priv, _ := ed25519.GenerateKey(nil)

	// Seed with a well-formed package and a few degenerate inputs.
	if pkg, err := Seal(&Manifest{AppID: "a", Entrypoint: "i.js"}, []byte("bundle-bytes"), key, priv); err == nil {
		f.Add(pkg)
	}
	if pkg, err := Seal(&Manifest{Entrypoint: "i.js"}, nil, key, priv); err == nil {
		f.Add(pkg)
	}
	f.Add([]byte{})
	f.Add([]byte(magic))
	f.Add(make([]byte, headerLen+64))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic. A package the fuzzer mutates will almost always
		// fail the signature check; that is the expected, safe outcome.
		_, _, _ = Open(data, key, pub)
	})
}

// FuzzOpenSigned exercises the structural parser + AEAD-open path that
// lives BEHIND the Ed25519 gate: the fuzzer's bytes become the signed
// body, so they pass signature verification and reach the length/nonce
// parsing and decryption logic with arbitrary shapes. None must panic.
func FuzzOpenSigned(f *testing.F) {
	key := make([]byte, aead.KeySize)
	for i := range key {
		key[i] = byte(i*7 + 1)
	}
	pub, priv, _ := ed25519.GenerateKey(nil)

	if pkg, err := Seal(&Manifest{Entrypoint: "i.js"}, []byte("body"), key, priv); err == nil {
		// Seed with the body (signature stripped) so the fuzzer starts from
		// a structurally valid header.
		f.Add(pkg[:len(pkg)-sign.SignatureSize])
	}
	f.Add(make([]byte, headerLen))

	f.Fuzz(func(t *testing.T, body []byte) {
		sig, err := sign.Sign(priv, body)
		if err != nil {
			return
		}
		pkg := append(append([]byte(nil), body...), sig...)
		_, _, _ = Open(pkg, key, pub)
	})
}
