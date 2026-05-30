//go:build backend

package policy

import "io"

// Mode identifies the active policy (introspected by other packages
// for logging).
const Mode = "backend"

func violate(_ Reason, _ string, exitFunc func(int), _ io.Writer) {
	// No diagnostics, no clean-up — just disappear.
	exitFunc(0)
}
