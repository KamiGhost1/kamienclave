// Package vm wraps goja with a deterministic lifecycle: a single
// runtime per invocation, ctx-driven interruption, and explicit
// teardown that zeroises the payload bytes.
//
// Сontract assumed by callers:
//
//   - the JS source supplied to Run is the only payload that ever
//     reaches the runtime; we never expose require()/eval-from-string
//     or any host primitive that lets the script self-exfiltrate;
//   - the host bridge is installed via Bind before Run; functions and
//     globals registered there form the entire surface the script can
//     see;
//   - Close() must be called even on error paths so that the source
//     buffer is wiped.
package vm

import (
	"context"
	"errors"
	"fmt"
	"runtime"

	"github.com/dop251/goja"

	"github.com/KamiGhost1/kamienclave/crypto/zeroize"
)

// ErrInterrupted is returned when Run is cancelled via the supplied
// context. We map goja's *InterruptedError onto this sentinel so the
// CLI doesn't have to type-assert on goja-internal types.
var ErrInterrupted = errors.New("vm: execution interrupted")

// Options tweak the runtime. All fields are optional.
type Options struct {
	// FieldNameMapper makes Go struct fields visible to JS using the
	// json tag; useful when binding DTO-style hosts.
	UseJSONTagMapper bool
}

// VM is a one-shot wrapper around goja.Runtime. Not safe for concurrent
// use; callers create one VM per JS execution.
type VM struct {
	rt     *goja.Runtime
	src    []byte // owned; zeroised on Close
	closed bool
}

// New constructs an empty runtime ready to be bound and fed a program.
func New(opts Options) *VM {
	rt := goja.New()
	if opts.UseJSONTagMapper {
		rt.SetFieldNameMapper(goja.TagFieldNameMapper("json", true))
	}
	return &VM{rt: rt}
}

// Bind exposes a Go value to JS under name. Use it for host functions
// or whitelisted objects. Returns an error only if the name is invalid.
func (v *VM) Bind(name string, value any) error {
	if v.closed {
		return errors.New("vm: closed")
	}
	return v.rt.Set(name, value)
}

// Runtime returns the underlying goja runtime for callers that need to
// register more complex objects (e.g. nested namespaces). The pointer
// must not be retained past Close.
func (v *VM) Runtime() *goja.Runtime {
	return v.rt
}

// Run compiles src under filename and executes it. The src buffer is
// consumed: the caller must not reuse it after the call returns — it
// is zeroised on the way out.
//
// If ctx is cancelled mid-execution Run aborts with ErrInterrupted.
// The returned value is the program's completion value (last expression
// statement); callers wanting a specific export should reach into the
// runtime's globals afterwards.
func (v *VM) Run(ctx context.Context, filename string, src []byte) (goja.Value, error) {
	if v.closed {
		return nil, errors.New("vm: closed")
	}

	v.src = src // own the buffer for teardown

	prog, err := goja.Compile(filename, string(src), false /* strict */)
	if err != nil {
		return nil, fmt.Errorf("vm: compile: %w", err)
	}
	// Compilation done; the original source string is no longer needed
	// by the runtime. Wipe it eagerly — Run may still take time and we
	// don't want the plaintext sitting around longer than necessary.
	zeroize.Bytes(v.src)

	// Wire context cancellation to goja's interrupt mechanism.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			v.rt.Interrupt(ctx.Err())
		case <-done:
		}
	}()

	val, err := v.rt.RunProgram(prog)
	if err != nil {
		var ie *goja.InterruptedError
		if errors.As(err, &ie) {
			return nil, ErrInterrupted
		}
		return nil, fmt.Errorf("vm: run: %w", err)
	}
	return val, nil
}

// Close releases references and runs GC twice to encourage early
// reclamation of heap-resident JS objects. Idempotent.
func (v *VM) Close() {
	if v.closed {
		return
	}
	v.closed = true
	zeroize.Bytes(v.src)
	v.src = nil
	v.rt = nil
	runtime.GC()
	runtime.GC()
}
