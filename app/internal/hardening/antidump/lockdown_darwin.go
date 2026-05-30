//go:build darwin

package antidump

import "golang.org/x/sys/unix"

func init() {
	Lockdown = darwinLockdown
	// Mlock/Munlock available via syscall on darwin; DontDump has no
	// direct equivalent (madvise(MADV_DONTNEED) is the closest but
	// far more aggressive — we leave it as a no-op).
	Mlock = darwinMlock
	Munlock = darwinMunlock
}

func darwinLockdown() error {
	return unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
}

func darwinMlock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return unix.Mlock(b)
}

func darwinMunlock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return unix.Munlock(b)
}
