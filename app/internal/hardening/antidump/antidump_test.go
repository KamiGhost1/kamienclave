package antidump

import "testing"

func TestLockdownIdempotent(t *testing.T) {
	// Lockdown should never crash and should be callable repeatedly.
	if err := Lockdown(); err != nil {
		t.Logf("Lockdown returned (best-effort): %v", err)
	}
	if err := Lockdown(); err != nil {
		t.Logf("Lockdown 2nd call: %v", err)
	}
}

func TestDontDumpAcceptsEmpty(t *testing.T) {
	if err := DontDump(nil); err != nil {
		t.Fatalf("DontDump(nil): %v", err)
	}
}

func TestMlockMunlockAcceptsEmpty(t *testing.T) {
	if err := Mlock(nil); err != nil {
		t.Fatalf("Mlock(nil): %v", err)
	}
	if err := Munlock(nil); err != nil {
		t.Fatalf("Munlock(nil): %v", err)
	}
}
