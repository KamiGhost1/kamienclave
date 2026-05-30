package bytecode

import (
	"errors"

	"golang.org/x/crypto/chacha20"
)

// Constant-pool encryption parameters. The key is a per-build secret
// shared by the server-side compiler and this interpreter (like the
// opcode table); the nonce is random per payload and stored in the
// header, so the same key can encrypt many payloads without keystream
// reuse.
const (
	ConstKeySize   = chacha20.KeySize   // 32
	ConstNonceSize = chacha20.NonceSize // 12
)

var (
	ErrKeySize     = errors.New("bytecode: const key must be 32 bytes")
	ErrKeyRequired = errors.New("bytecode: encrypted constants require a key")
)

// xorConsts applies the ChaCha20 keystream to buf in place. Encryption
// and decryption are the same operation.
func xorConsts(buf, key, nonce []byte) error {
	c, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return err
	}
	c.XORKeyStream(buf, buf)
	return nil
}
