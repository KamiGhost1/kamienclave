// Package hardening is the single entrypoint main() calls to apply
// every runtime defence we have: anti-dump lockdown, anti-debugger
// probes (early + background), self-binary integrity check, and the
// fatal-signal zeroize handler.
//
// Init returns a stop function the caller invokes during normal
// shutdown; the background probe goroutine and the signal handler exit
// when stop is called.
package hardening

import (
	"time"

	"github.com/KamiGhost1/kamienclave/internal/hardening/antidebug"
	"github.com/KamiGhost1/kamienclave/internal/hardening/antidump"
	"github.com/KamiGhost1/kamienclave/internal/hardening/integrity"
	"github.com/KamiGhost1/kamienclave/internal/hardening/policy"
	"github.com/KamiGhost1/kamienclave/internal/hardening/signals"
)

// Mode echoes the policy package's compile-time mode ("public" or
// "backend"). Exposed so the CLI can print it in `kamienclave version`.
const Mode = policy.Mode

// Init applies all hardening primitives in order. Safe to call once
// at the top of main(); calling it multiple times is harmless but
// wasted work.
func Init() (stop func()) {
	// Lockdown first so any subsequent crash doesn't produce a core.
	// Errors are best-effort: a container without CAP_SYS_PTRACE will
	// happily refuse PR_SET_DUMPABLE — that's fine, we still cleared
	// what we could.
	_ = antidump.Lockdown()

	integrity.Enforce()
	antidebug.EarlyCheck()

	stopProbe := antidebug.StartBackground(500*time.Millisecond, 3*time.Second)
	stopSignals := signals.Install()
	return func() {
		stopSignals()
		stopProbe()
	}
}
