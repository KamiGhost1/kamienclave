// Package apprunner is the client-side core of full-application delivery
// (режим B): given a fetched .encpkg and the license bundle, it verifies
// and decrypts the application, checks integrity, and hands the bundle to
// a Launcher that actually starts Node.
//
// The Launcher is an interface so the verify/decrypt core is testable
// without Node, and so the in-memory (no-disk) launch can be a
// platform-specific implementation (Linux memfd; see launcher_linux.go).
package apprunner

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/KamiGhost1/kamienclave/crypto/zeroize"
	"github.com/KamiGhost1/kamienclave/encpkg"
)

// Launcher starts the decrypted application. Implementations decide how
// the bytes reach Node (memfd/fd, --eval, tmpfs). It must not return
// until the application exits (or ctx is cancelled).
type Launcher interface {
	Launch(ctx context.Context, app App) error
}

// App is the decrypted, verified application ready to run.
type App struct {
	Manifest *encpkg.Manifest
	Bundle   []byte            // the application bytes (e.g. ncc single-file JS)
	Env      map[string]string // resolved env passthrough (name -> value)
}

var (
	ErrIntegrity = errors.New("apprunner: payload integrity check failed")
	ErrManifest  = errors.New("apprunner: invalid manifest")
)

// Open verifies+decrypts an .encpkg into a runnable App. envLookup
// resolves the manifest's env_passthrough names to values (e.g.
// os.Getenv); pass nil to skip env resolution.
func Open(pkg, appKey []byte, verifyKey ed25519.PublicKey, envLookup func(string) (string, bool)) (App, error) {
	manifest, bundle, err := encpkg.Open(pkg, appKey, verifyKey)
	if err != nil {
		return App{}, err
	}
	if manifest.Entrypoint == "" {
		return App{}, fmt.Errorf("%w: empty entrypoint", ErrManifest)
	}
	if manifest.PayloadSHA256 != "" {
		sum := sha256.Sum256(bundle)
		if hex.EncodeToString(sum[:]) != manifest.PayloadSHA256 {
			zeroize.Bytes(bundle)
			return App{}, ErrIntegrity
		}
	}

	env := map[string]string{}
	if envLookup != nil {
		for _, name := range manifest.EnvPassthrough {
			if v, ok := envLookup(name); ok {
				env[name] = v
			}
		}
	}
	return App{Manifest: manifest, Bundle: bundle, Env: env}, nil
}

// Run opens the package and launches it via l. The app bundle is
// zeroised after the launcher returns.
func Run(ctx context.Context, l Launcher, pkg, appKey []byte, verifyKey ed25519.PublicKey, envLookup func(string) (string, bool)) error {
	app, err := Open(pkg, appKey, verifyKey, envLookup)
	if err != nil {
		return err
	}
	defer zeroize.Bytes(app.Bundle)
	return l.Launch(ctx, app)
}
