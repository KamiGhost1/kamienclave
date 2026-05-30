//go:build windows

package antidump

import "golang.org/x/sys/windows"

func init() {
	Lockdown = windowsLockdown
	// VirtualLock provides per-region locking; DontDump has no direct
	// counterpart short of mitigation policies that vary by Windows
	// version. Left as no-op for the v1.
	Mlock = windowsMlock
	Munlock = windowsMunlock
}

func windowsLockdown() error {
	// Suppress the "Application has crashed" UI which can include a
	// memory dump prompt. SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX.
	prev := windows.SetErrorMode(0x0001 | 0x0002)
	// Re-OR with whatever was there; callers shouldn't depend on
	// observing the previous value.
	windows.SetErrorMode(prev | 0x0001 | 0x0002)
	return nil
}

func windowsMlock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return windows.VirtualLock(uintptr(_first(b)), uintptr(len(b)))
}

func windowsMunlock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return windows.VirtualUnlock(uintptr(_first(b)), uintptr(len(b)))
}

func _first(b []byte) *byte { return &b[0] }
