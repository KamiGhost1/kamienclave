package license

import (
	"embed"
	"errors"
	"io/fs"
	"os"
)

//go:embed assets
var embeddedAssets embed.FS

// EmbeddedBlobName is the file inside the embedded assets directory
// that the server build pipeline drops the per-license blob into.
const EmbeddedBlobName = "license.lic"

// ErrNoEmbeddedBlob is returned when no blob was embedded at build time.
var ErrNoEmbeddedBlob = errors.New("license: no embedded blob")

// LoadEmbedded returns the encrypted blob that was baked into the
// binary at compile time, or ErrNoEmbeddedBlob if none was provided.
// Callers should then fall back to a --license-file argument.
func LoadEmbedded() ([]byte, error) {
	data, err := embeddedAssets.ReadFile("assets/" + EmbeddedBlobName)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNoEmbeddedBlob
		}
		return nil, err
	}
	if len(data) == 0 {
		return nil, ErrNoEmbeddedBlob
	}
	return data, nil
}

// LoadFile reads a blob from disk.
func LoadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
