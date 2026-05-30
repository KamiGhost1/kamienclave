// Package blob defines the on-disk format that protects the
// per-license secrets bundled with each kamienclave binary.
//
// Layout (little-endian, network-order bytes where noted):
//
//	+-----------+-----------+--------------------+
//	| magic 4B  | "DLBV"    | identifies the file|
//	+-----------+-----------+--------------------+
//	| ver 1B    | 1         | format version     |
//	+-----------+-----------+--------------------+
//	| t   u32 LE | argon2id "time" parameter      |
//	+-----------+--------------------------------+
//	| m   u32 LE | argon2id memory in KiB         |
//	+-----------+--------------------------------+
//	| p    u8    | argon2id parallelism (lanes)   |
//	+-----------+--------------------------------+
//	| slen u8    | salt length                    |
//	| salt slen  | KDF salt                       |
//	+-----------+--------------------------------+
//	| nonce 12B  | AES-256-GCM nonce              |
//	+-----------+--------------------------------+
//	| ct varlen  | AES-256-GCM(plaintext, aad=hdr)|
//	+-----------+--------------------------------+
//
// The AEAD AAD is the full header preceding the ciphertext — any
// tampering with KDF parameters, salt or nonce fails authentication.
package blob

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"

	"github.com/KamiGhost1/kamienclave/crypto/aead"
	"github.com/KamiGhost1/kamienclave/crypto/zeroize"
)

const (
	Magic   = "DLBV"
	Version = 1

	// SaltSize is the default Argon2id salt length. The header carries
	// the actual length so future versions can rotate this without
	// breaking old blobs.
	SaltSize = 16
)

// KDFParams describes the Argon2id work factors. The defaults are a
// 2026-era compromise between desktop UX (~250 ms unlock on a typical
// laptop) and resistance to offline brute force.
type KDFParams struct {
	Time        uint32 // passes
	MemoryKiB   uint32 // memory in KiB
	Parallelism uint8  // lanes
}

// Default returns a sensible parameter set.
func Default() KDFParams {
	return KDFParams{
		Time:        2,
		MemoryKiB:   64 * 1024, // 64 MiB
		Parallelism: 1,
	}
}

// Errors.
var (
	ErrBadMagic        = errors.New("blob: bad magic")
	ErrUnknownVersion  = errors.New("blob: unknown version")
	ErrTruncatedHeader = errors.New("blob: truncated header")
	ErrTruncatedBody   = errors.New("blob: truncated body")
	ErrEmptyPassphrase = errors.New("blob: empty passphrase")
)

// Seal encrypts plaintext under passphrase and returns a marshalled
// blob. The passphrase is read but not mutated; the caller remains
// responsible for wiping it once the blob is on its way to disk.
func Seal(passphrase, plaintext []byte, params KDFParams) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, ErrEmptyPassphrase
	}
	if params.Time == 0 || params.MemoryKiB == 0 || params.Parallelism == 0 {
		return nil, errors.New("blob: kdf params must be > 0")
	}

	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("blob: salt: %w", err)
	}

	header, err := marshalHeader(params, salt, mustRandomNonce())
	if err != nil {
		return nil, err
	}

	key := deriveKey(passphrase, salt, params)
	defer zeroize.Bytes(key)

	// Re-extract the nonce we encoded so we feed the AEAD the same value.
	nonce := header[len(header)-aead.NonceSize:]
	ct, err := aead.SealWithNonce(key, nonce, plaintext, header)
	if err != nil {
		return nil, fmt.Errorf("blob: seal: %w", err)
	}

	out := make([]byte, 0, len(header)+len(ct))
	out = append(out, header...)
	out = append(out, ct...)
	return out, nil
}

// Open verifies and decrypts a blob. Returns the plaintext or an error.
// Plaintext ownership transfers to the caller — wipe it via zeroize.
func Open(passphrase, blob []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, ErrEmptyPassphrase
	}

	params, salt, nonce, ctOffset, err := parseHeader(blob)
	if err != nil {
		return nil, err
	}
	header := blob[:ctOffset]
	ct := blob[ctOffset:]

	key := deriveKey(passphrase, salt, params)
	defer zeroize.Bytes(key)

	pt, err := aead.OpenWithNonce(key, nonce, ct, header)
	if err != nil {
		return nil, fmt.Errorf("blob: open: %w", err)
	}
	return pt, nil
}

// --- internals -------------------------------------------------------

func deriveKey(passphrase, salt []byte, p KDFParams) []byte {
	return argon2.IDKey(passphrase, salt, p.Time, p.MemoryKiB, p.Parallelism, aead.KeySize)
}

func mustRandomNonce() []byte {
	n := make([]byte, aead.NonceSize)
	if _, err := io.ReadFull(rand.Reader, n); err != nil {
		// Failing to read from the OS CSPRNG is a fatal-class error;
		// callers can't recover. Panicking here keeps the API tidy and
		// is consistent with crypto/rand idioms.
		panic(fmt.Sprintf("blob: rand.Read failed: %v", err))
	}
	return n
}

func marshalHeader(p KDFParams, salt, nonce []byte) ([]byte, error) {
	if len(salt) == 0 || len(salt) > 255 {
		return nil, errors.New("blob: bad salt length")
	}
	if len(nonce) != aead.NonceSize {
		return nil, fmt.Errorf("blob: nonce must be %d bytes", aead.NonceSize)
	}

	var b bytes.Buffer
	b.WriteString(Magic)
	b.WriteByte(Version)
	_ = binary.Write(&b, binary.LittleEndian, p.Time)
	_ = binary.Write(&b, binary.LittleEndian, p.MemoryKiB)
	b.WriteByte(p.Parallelism)
	b.WriteByte(byte(len(salt)))
	b.Write(salt)
	b.Write(nonce)
	return b.Bytes(), nil
}

func parseHeader(buf []byte) (params KDFParams, salt, nonce []byte, ctOffset int, err error) {
	const fixedPrefix = 4 + 1 + 4 + 4 + 1 + 1 // magic+ver+t+m+p+slen
	if len(buf) < fixedPrefix {
		err = ErrTruncatedHeader
		return
	}
	if string(buf[:4]) != Magic {
		err = ErrBadMagic
		return
	}
	if buf[4] != Version {
		err = ErrUnknownVersion
		return
	}
	params.Time = binary.LittleEndian.Uint32(buf[5:9])
	params.MemoryKiB = binary.LittleEndian.Uint32(buf[9:13])
	params.Parallelism = buf[13]
	slen := int(buf[14])

	saltStart := fixedPrefix
	saltEnd := saltStart + slen
	nonceEnd := saltEnd + aead.NonceSize
	if len(buf) < nonceEnd {
		err = ErrTruncatedHeader
		return
	}
	salt = buf[saltStart:saltEnd]
	nonce = buf[saltEnd:nonceEnd]
	ctOffset = nonceEnd

	if len(buf) <= ctOffset {
		err = ErrTruncatedBody
		return
	}
	return
}
