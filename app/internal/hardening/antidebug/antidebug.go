// Package antidebug runs platform-specific debugger probes and
// reports any positive sighting through the policy package.
//
// EarlyCheck is fast and synchronous; call it as the first thing in
// main(). StartBackground spawns a goroutine that re-probes at a
// jittered interval so attaching after startup also gets caught.
package antidebug

import (
	"math/rand"
	"sync"
	"time"

	"github.com/KamiGhost1/kamienclave/internal/hardening/policy"
)

// Probe is the platform-specific check. It returns a non-empty detail
// string if a debugger is detected, or empty otherwise.
var Probe func() string = func() string { return "" }

// EarlyCheck runs Probe once and triggers policy.Violate on a positive.
// Suitable for main().
func EarlyCheck() {
	if d := Probe(); d != "" {
		policy.Violate(policy.ReasonDebugger, d)
	}
}

// StartBackground launches a re-probe goroutine. The interval drifts
// randomly between min and max so attackers can't time their attach
// against a fixed cadence. The returned stop function blocks until
// the goroutine has actually exited — important for the race
// detector and for tests that swap policy hooks around it.
func StartBackground(min, max time.Duration) (stop func()) {
	if min <= 0 || max < min {
		min, max = 500*time.Millisecond, 3*time.Second
	}
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Local PRNG — math/rand global is fine but we don't want to
		// share it with the rest of the program.
		src := rand.New(rand.NewSource(time.Now().UnixNano()))
		for {
			delta := max - min
			d := min + time.Duration(src.Int63n(int64(delta)+1))
			select {
			case <-time.After(d):
				if detail := Probe(); detail != "" {
					policy.Violate(policy.ReasonDebugger, detail)
				}
			case <-done:
				return
			}
		}
	}()
	return func() {
		close(done)
		wg.Wait()
	}
}
