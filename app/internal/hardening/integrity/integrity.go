// Package integrity verifies that the running binary has not been
// patched since the build pipeline stamped it.
//
// Scheme (draft 0.2): the post-build `stamp` tool appends a fixed
// trailer to the binary — an 8-byte magic followed by the SHA-256 of
// everything before it:
//
//	[ ... binary ... ][ "DLTRINTG" ][ 32-byte sha256(binary) ]
//
// At runtime Check reads its own file, splits off the trailer, and
// recomputes the hash over the body. This sidesteps the circularity of
// embedding a hash of the whole file inside that same file, and — unlike
// an -ldflags string — it is applied after garble runs, so obfuscation
// can't disturb it. Trailing bytes after the executable's structured
// format are ignored by OS loaders, so the stamped binary still runs.
//
// An unstamped binary (typical of dev `go build`) reports
// ErrNoExpectedHash and Enforce treats that as a soft miss.
package integrity

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"os"

	"github.com/KamiGhost1/kamienclave/internal/hardening/policy"
)

const (
	trailerMagic = "DLTRINTG" // 8 bytes
	hashSize     = sha256.Size
	trailerSize  = len(trailerMagic) + hashSize
)

var (
	// ErrNoExpectedHash signals an unstamped binary; not a violation.
	ErrNoExpectedHash = errors.New("integrity: binary is not stamped")
	// ErrMismatch means the body hash differs from the stamped value.
	ErrMismatch = errors.New("integrity: hash mismatch")
)

// Check computes the body hash of the running executable and compares it
// to the stamped trailer.
func Check() error {
	path, err := os.Executable()
	if err != nil {
		return err
	}
	return verify(path)
}

// verify is the file-level core, split out so tests can target an
// arbitrary path rather than the test binary itself.
func verify(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !hasTrailer(data) {
		return ErrNoExpectedHash
	}
	stored := data[len(data)-hashSize:]
	sum := sha256.Sum256(data[:len(data)-trailerSize])
	if subtle.ConstantTimeCompare(sum[:], stored) != 1 {
		return ErrMismatch
	}
	return nil
}

// Stamp appends (or refreshes) the integrity trailer on the binary at
// path. Idempotent: an existing trailer is stripped before re-hashing.
func Stamp(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	body := stripTrailer(data)
	sum := sha256.Sum256(body)

	out := make([]byte, 0, len(body)+trailerSize)
	out = append(out, body...)
	out = append(out, trailerMagic...)
	out = append(out, sum[:]...)
	return os.WriteFile(path, out, 0o755)
}

func hasTrailer(data []byte) bool {
	if len(data) < trailerSize {
		return false
	}
	magicStart := len(data) - trailerSize
	return string(data[magicStart:magicStart+len(trailerMagic)]) == trailerMagic
}

func stripTrailer(data []byte) []byte {
	if hasTrailer(data) {
		return data[:len(data)-trailerSize]
	}
	return data
}

// Enforce runs Check and fires policy only on a real mismatch.
// ErrNoExpectedHash (unstamped dev build) is a soft miss.
func Enforce() {
	switch err := Check(); {
	case err == nil:
		return
	case errors.Is(err, ErrNoExpectedHash):
		return
	default:
		policy.Violate(policy.ReasonIntegrity, err.Error())
	}
}
