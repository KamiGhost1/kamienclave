package policy

import (
	"bytes"
	"strings"
	"testing"
)

func TestViolateRespectsPolicy(t *testing.T) {
	// Save & restore.
	defer SetExitFunc(func(int) {})
	defer SetStderr(nil)

	calledWith := -1
	SetExitFunc(func(code int) { calledWith = code })
	buf := &bytes.Buffer{}
	SetStderr(buf)

	Violate(ReasonDebugger, "test detail")

	switch Mode {
	case "public":
		if calledWith != -1 {
			t.Fatalf("public mode must not call exit; got code %d", calledWith)
		}
		if !strings.Contains(buf.String(), "debugger detected") {
			t.Fatalf("public stderr missing reason: %q", buf.String())
		}
	case "backend":
		if calledWith != 0 {
			t.Fatalf("backend mode must call exit(0); got %d", calledWith)
		}
		if buf.Len() != 0 {
			t.Fatalf("backend mode must not write to stderr: %q", buf.String())
		}
	default:
		t.Fatalf("unknown policy mode: %q", Mode)
	}
}
