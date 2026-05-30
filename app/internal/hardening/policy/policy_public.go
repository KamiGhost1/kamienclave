//go:build !backend

package policy

import (
	"fmt"
	"io"
)

// Mode identifies the active policy (introspected by other packages
// for logging).
const Mode = "public"

func violate(reason Reason, detail string, _ func(int), sw io.Writer) {
	if sw == nil {
		return
	}
	_, _ = fmt.Fprintf(sw, "enclave hardening: %s: %s\n", reason, detail)
}
