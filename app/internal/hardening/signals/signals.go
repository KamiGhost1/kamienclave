// Package signals installs handlers for process-termination signals so
// that registered secrets are wiped before kamienclave dies, then reports
// the event through policy.
//
// Caveat on synchronous faults: a genuine SIGSEGV/SIGBUS raised by the
// program itself is handled by the Go runtime and generally does not
// reach an os/signal handler, so the runtime — not this package — owns
// that path. We still register for them so that an externally delivered
// SIGSEGV/SIGBUS (e.g. `kill -SEGV`) triggers cleanup, and we cover the
// asynchronously delivered termination signals (SIGTERM/SIGINT/...)
// which are the realistic case.
package signals

import (
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/KamiGhost1/kamienclave/internal/hardening/policy"
	"github.com/KamiGhost1/kamienclave/internal/hardening/secrets"
)

// exitFunc is the terminator invoked after cleanup. Overridable for
// tests so a delivered signal doesn't kill the test binary.
var (
	mu       sync.Mutex
	exitFunc = os.Exit
)

// SetExitFunc overrides the post-cleanup terminator. Tests only.
func SetExitFunc(f func(int)) {
	mu.Lock()
	exitFunc = f
	mu.Unlock()
}

var trapped = []os.Signal{
	syscall.SIGTERM,
	syscall.SIGINT,
	syscall.SIGHUP,
	syscall.SIGQUIT,
	syscall.SIGABRT,
	syscall.SIGSEGV,
	syscall.SIGBUS,
}

// Install starts a goroutine that waits for a trapped signal, runs the
// zeroize hooks, reports via policy, and terminates. The returned stop
// function tears the handler down (used on the normal-exit path).
func Install() (stop func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, trapped...)

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case sig := <-ch:
			handle(sig)
		case <-done:
		}
	}()
	return func() {
		signal.Stop(ch)
		close(done)
		wg.Wait()
	}
}

// handle performs the cleanup-then-terminate sequence for sig. Split out
// so tests can exercise it without delivering a real signal.
func handle(sig os.Signal) {
	secrets.WipeAll()
	policy.Violate(policy.ReasonSignal, sig.String())
	// In the backend build policy.Violate has already exited; this is the
	// public-build / test path where we still must terminate on a real
	// termination signal.
	mu.Lock()
	ef := exitFunc
	mu.Unlock()
	ef(1)
}
