// Package secrets keeps a process-global registry of sensitive byte
// buffers to wipe on a fatal path — a termination signal or an
// unrecovered panic — where ordinary deferred zeroize calls would not
// run. Registration is best-effort and concurrency-safe.
//
// This complements, not replaces, the normal pattern of wiping secrets
// with a defer on the happy path; it is the safety net for the abnormal
// exit (TECHNICAL.md §8.2: "перехват SIGSEGV/SIGBUS/SIGTERM с zeroize
// hooks").
package secrets

import (
	"sync"

	"github.com/KamiGhost1/kamienclave/crypto/zeroize"
)

var (
	mu   sync.Mutex
	bufs [][]byte
)

// Register adds b to the set wiped by WipeAll. The registry holds the
// slice header, so the caller's buffer is wiped in place. Empty slices
// are ignored.
func Register(b []byte) {
	if len(b) == 0 {
		return
	}
	mu.Lock()
	bufs = append(bufs, b)
	mu.Unlock()
}

// WipeAll zeroises every registered buffer and clears the registry. It
// is safe to call more than once (e.g. once from a signal handler and
// again from a panic guard).
func WipeAll() {
	mu.Lock()
	defer mu.Unlock()
	for _, b := range bufs {
		zeroize.Bytes(b)
	}
	bufs = nil
}

// Count returns the number of registered buffers. Intended for tests.
func Count() int {
	mu.Lock()
	defer mu.Unlock()
	return len(bufs)
}
