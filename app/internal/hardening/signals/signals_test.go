package signals

import (
	"io"
	"os"
	"syscall"
	"testing"

	"github.com/KamiGhost1/kamienclave/internal/hardening/policy"
	"github.com/KamiGhost1/kamienclave/internal/hardening/secrets"
)

func TestHandleWipesSecretsAndExits(t *testing.T) {
	// Capture the terminator instead of dying.
	code := -1
	SetExitFunc(func(c int) { code = c })
	defer SetExitFunc(os.Exit)

	// In the backend build policy.Violate would os.Exit(0) and kill the
	// test; stub it. In the public build it warns — silence that.
	policy.SetExitFunc(func(int) {})
	defer policy.SetExitFunc(os.Exit)
	policy.SetStderr(io.Discard)
	defer policy.SetStderr(os.Stderr)

	secret := []byte{7, 7, 7, 7}
	secrets.Register(secret)

	handle(syscall.SIGTERM)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	for i, v := range secret {
		if v != 0 {
			t.Fatalf("secret[%d] = %d, not wiped on signal", i, v)
		}
	}
}

func TestInstallStopDoesNotHang(t *testing.T) {
	stop := Install()
	stop() // must return promptly even though no signal arrived
}
