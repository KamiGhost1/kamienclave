//go:build linux

package antidump

import (
	"errors"

	"golang.org/x/sys/unix"
)

func init() {
	Lockdown = linuxLockdown
	DontDump = linuxDontDump
	Mlock = linuxMlock
	Munlock = linuxMunlock
}

func linuxLockdown() error {
	var firstErr error
	keep := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	keep(unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0))
	keep(unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}))
	// PR_SET_PTRACER=0 disallows ptrace from non-parents (the YAMA LSM
	// honours this); harmless where YAMA is absent.
	keep(unix.Prctl(unix.PR_SET_PTRACER, 0, 0, 0, 0))
	return firstErr
}

func linuxDontDump(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return unix.Madvise(b, unix.MADV_DONTDUMP)
}

func linuxMlock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	if err := unix.Mlock(b); err != nil {
		// Most common cause: RLIMIT_MEMLOCK too low (default 64 KiB on
		// many distros and most containers). Translate that to a tame
		// "not permitted" error rather than letting callers see a raw
		// ENOMEM and panic.
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.ENOMEM) {
			return ErrLockNotPermitted
		}
		return err
	}
	return nil
}

func linuxMunlock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return unix.Munlock(b)
}

// ErrLockNotPermitted is returned by Mlock when the kernel refuses due
// to insufficient RLIMIT_MEMLOCK or capabilities. Callers can ignore
// it without compromising correctness.
var ErrLockNotPermitted = errors.New("antidump: mlock not permitted")
