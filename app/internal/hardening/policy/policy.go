// Package policy is the single decision point for how kamienclave reacts
// to a hardening-violation signal (debugger attached, integrity check
// failed, suspicious environment).
//
// Two policies exist, selected at build time:
//
//   - "public": warn to stderr and continue. Intended for the
//     open-source demonstration build where the user is allowed to
//     poke at the running process.
//
//   - "backend": call exitFunc(0) immediately, without any diagnostic
//     output. Selected by building with `-tags backend`.
//
// Tests can override exitFunc to observe behaviour without actually
// terminating the test process.
package policy

import (
	"io"
	"os"
	"sync"
)

// Reason identifies why the policy is being invoked. Backend builds
// ignore it; the public build prints it.
type Reason string

const (
	ReasonDebugger  Reason = "debugger detected"
	ReasonIntegrity Reason = "integrity check failed"
	ReasonDump      Reason = "anti-dump lockdown failed"
	ReasonSignal    Reason = "fatal signal received"
	ReasonPanic     Reason = "unrecovered panic"
)

// ExitFunc and Stderr are exported so tests can swap them.
var (
	mu       sync.Mutex
	exitFunc           = os.Exit
	stderr   io.Writer = os.Stderr
)

// SetExitFunc overrides the function called on a backend-mode violation.
// Intended for tests only.
func SetExitFunc(f func(int)) {
	mu.Lock()
	defer mu.Unlock()
	exitFunc = f
}

// SetStderr overrides the writer used for public-mode warnings.
// Intended for tests only.
func SetStderr(w io.Writer) {
	mu.Lock()
	defer mu.Unlock()
	stderr = w
}

// Violate triggers the configured response. It always returns — even
// in backend mode the exitFunc may be a test stub. Callers that want
// to make extra-sure should still bail out after calling.
func Violate(reason Reason, detail string) {
	mu.Lock()
	ef := exitFunc
	sw := stderr
	mu.Unlock()
	violate(reason, detail, ef, sw)
}
