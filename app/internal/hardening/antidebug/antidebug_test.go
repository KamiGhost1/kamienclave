package antidebug

import (
	"bytes"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KamiGhost1/kamienclave/internal/hardening/policy"
)

func TestStartBackgroundFiresOnPositiveProbe(t *testing.T) {
	// Force a positive probe and observe policy.Violate firing.
	orig := Probe
	defer func() { Probe = orig }()

	var fired atomic.Int32
	Probe = func() string {
		fired.Add(1)
		return "synthetic"
	}

	var exitCalls atomic.Int32
	policy.SetExitFunc(func(int) { exitCalls.Add(1) })
	defer policy.SetExitFunc(func(int) {})

	buf := &bytes.Buffer{}
	policy.SetStderr(buf)
	defer policy.SetStderr(nil)

	stop := StartBackground(5*time.Millisecond, 10*time.Millisecond)
	time.Sleep(60 * time.Millisecond)
	stop()

	if fired.Load() == 0 {
		t.Fatal("Probe never fired")
	}

	switch policy.Mode {
	case "public":
		if buf.Len() == 0 {
			t.Fatal("public mode must warn on stderr")
		}
	case "backend":
		if exitCalls.Load() == 0 {
			t.Fatal("backend mode must call exitFunc")
		}
	}
}

func TestEarlyCheckNoDebugger(t *testing.T) {
	orig := Probe
	defer func() { Probe = orig }()

	Probe = func() string { return "" }

	var exitCalls atomic.Int32
	policy.SetExitFunc(func(int) { exitCalls.Add(1) })
	defer policy.SetExitFunc(func(int) {})

	EarlyCheck()
	if exitCalls.Load() != 0 {
		t.Fatal("EarlyCheck must not exit when probe returns empty")
	}
}
