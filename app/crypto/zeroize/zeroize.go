// Package zeroize provides best-effort overwrite primitives for sensitive
// byte buffers. Go's garbage collector and compiler can theoretically move
// or elide writes that have no observable effect; we mitigate this by
// referencing the buffer through a runtime.KeepAlive after the wipe and by
// keeping the loop opaque to the compiler.
//
// This is best-effort by design: real defence-in-depth comes from also
// minimising the lifetime of sensitive buffers and from mlock/MADV_DONTDUMP
// at the platform layer (see TECHNICAL.md §8.2).
package zeroize

import "runtime"

// Bytes overwrites b with zero bytes. The runtime.KeepAlive at the end
// prevents the compiler from treating the loop as dead code on the
// grounds that b is no longer used after the call.
func Bytes(b []byte) {
	if len(b) == 0 {
		return
	}
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// Multi wipes every supplied buffer. Nil entries are ignored.
func Multi(bufs ...[]byte) {
	for _, b := range bufs {
		Bytes(b)
	}
}
