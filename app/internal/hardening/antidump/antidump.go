// Package antidump applies platform-specific lockdown that makes a
// running kamienclave process harder to dump:
//
//   - core dumps are disabled at the rlimit level;
//   - ptrace from non-parents is denied where the OS supports it;
//   - sensitive memory regions can be opted out of dump inclusion via
//     DontDump.
//
// Lockdown is best-effort. A failing call returns a non-nil error
// only on Linux for diagnostic purposes; callers are expected to log
// and continue, because some sandboxes legitimately refuse these
// syscalls.
package antidump

// Lockdown applies every platform-specific anti-dump primitive
// available. Safe to call multiple times.
var Lockdown func() error = func() error { return nil }

// DontDump marks the supplied byte range as excluded from process
// dumps where the OS supports it (Linux: MADV_DONTDUMP). On other
// platforms the call is a no-op.
var DontDump func(b []byte) error = func([]byte) error { return nil }

// Mlock attempts to lock the supplied byte range into physical RAM so
// it never reaches swap. May fail without sufficient RLIMIT_MEMLOCK;
// callers should treat success as a bonus, not a guarantee.
var Mlock func(b []byte) error = func([]byte) error { return nil }

// Munlock undoes Mlock. Idempotent.
var Munlock func(b []byte) error = func([]byte) error { return nil }
