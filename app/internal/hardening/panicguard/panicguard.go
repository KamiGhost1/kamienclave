// Package panicguard converts an unrecovered panic into a controlled
// teardown: wipe registered secrets, report through policy, and then —
// on the backend build — let policy vanish the process without printing
// a Go stack trace (which would leak symbol and layout information). On
// the public/dev build it re-panics so developers keep the trace.
//
// Usage: defer panicguard.Recover() as the first statement of main (and
// of any long-lived goroutine that handles sensitive data). Recover must
// be deferred directly — it calls the builtin recover() itself, which
// only works one frame up from the deferred call.
package panicguard

import (
	"fmt"

	"github.com/KamiGhost1/kamienclave/internal/hardening/policy"
	"github.com/KamiGhost1/kamienclave/internal/hardening/secrets"
)

// Recover handles a panic propagating through the deferred frame. With
// no panic in flight it is a no-op.
func Recover() {
	r := recover()
	if r == nil {
		return
	}
	secrets.WipeAll()
	policy.Violate(policy.ReasonPanic, fmt.Sprint(r))

	// Backend: policy.Violate has already called exit(0); reaching here
	// means either the public build or a test that stubbed exit. In the
	// public build we re-raise so the developer sees the original panic.
	if policy.Mode != "backend" {
		panic(r)
	}
}
