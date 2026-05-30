package panicguard_test

import (
	"io"
	"os"
	"testing"

	"github.com/KamiGhost1/kamienclave/internal/hardening/panicguard"
	"github.com/KamiGhost1/kamienclave/internal/hardening/policy"
	"github.com/KamiGhost1/kamienclave/internal/hardening/secrets"
)

// runGuarded runs fn behind panicguard.Recover and returns whatever
// value (if any) propagated past the guard — nil when Recover swallowed
// the panic.
func runGuarded(fn func()) (escaped any) {
	defer func() { escaped = recover() }()
	func() {
		defer panicguard.Recover()
		fn()
	}()
	return
}

func TestRecoverWipesAndReports(t *testing.T) {
	policy.SetStderr(io.Discard)
	defer policy.SetStderr(os.Stderr)

	// Stub policy exit so the backend build doesn't os.Exit the test.
	exited := false
	policy.SetExitFunc(func(int) { exited = true })
	defer policy.SetExitFunc(os.Exit)

	secret := []byte{5, 5, 5}
	secrets.Register(secret)

	escaped := runGuarded(func() { panic("boom") })

	// Secrets are wiped regardless of build.
	for i, v := range secret {
		if v != 0 {
			t.Fatalf("secret[%d] = %d, not wiped on panic", i, v)
		}
	}

	if policy.Mode == "backend" {
		if !exited {
			t.Fatal("backend: expected policy exit on panic")
		}
		if escaped != nil {
			t.Fatalf("backend: panic should not be re-raised, got %v", escaped)
		}
	} else {
		if escaped != "boom" {
			t.Fatalf("public: expected re-raised panic boom, got %v", escaped)
		}
	}
}

func TestRecoverNoPanicIsNoop(t *testing.T) {
	func() {
		defer panicguard.Recover()
	}()
}
