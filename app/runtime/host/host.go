// Package host defines the whitelisted bridge between the in-memory JS
// payload and the Go process hosting it. The surface is intentionally
// tiny — only what we explicitly grant gets through.
//
// Anything not registered here is invisible to the script. There is no
// require(), no fs, no child_process, no network primitive of any kind.
// Subsequent stages may add HTTP egress, but only via this package so
// that all allowed I/O lives behind one audit-friendly boundary.
package host

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/KamiGhost1/kamienclave/runtime/vm"
)

// Logger is what the script's log() function calls into. The CLI wires
// it to os.Stdout in dev mode; the backend build wires it to an in-mem
// ring buffer (or /dev/null) so the script can't tee secrets to the
// terminal.
type Logger interface {
	Logf(format string, args ...any)
}

// WriterLogger adapts an io.Writer to Logger.
type WriterLogger struct{ W io.Writer }

func (w WriterLogger) Logf(format string, args ...any) {
	if w.W == nil {
		return
	}
	_, _ = fmt.Fprintf(w.W, format+"\n", args...)
}

// DiscardLogger satisfies Logger but drops everything.
type DiscardLogger struct{}

func (DiscardLogger) Logf(string, ...any) {}

// Bridge holds the configured surface. Install() registers it on a VM.
type Bridge struct {
	Log      Logger
	Env      map[string]string // exposed via env.get(key)
	MaxSleep time.Duration     // upper bound on sleep(ms); 0 => 5s default
}

// New returns a Bridge with safe defaults: discard logger, no env, 5s
// sleep cap.
func New() *Bridge {
	return &Bridge{
		Log:      DiscardLogger{},
		Env:      map[string]string{},
		MaxSleep: 5 * time.Second,
	}
}

// Install binds every host primitive onto the supplied VM. Call this
// once before vm.Run.
func (b *Bridge) Install(v *vm.VM) error {
	if v == nil {
		return errors.New("host: nil vm")
	}
	if b.Log == nil {
		b.Log = DiscardLogger{}
	}
	if b.Env == nil {
		b.Env = map[string]string{}
	}
	if b.MaxSleep == 0 {
		b.MaxSleep = 5 * time.Second
	}

	rt := v.Runtime()
	if rt == nil {
		return errors.New("host: vm has nil runtime")
	}

	if err := v.Bind("log", b.logFunc()); err != nil {
		return err
	}

	envObj := rt.NewObject()
	if err := envObj.Set("get", b.envGet); err != nil {
		return err
	}
	if err := envObj.Set("keys", b.envKeys); err != nil {
		return err
	}
	if err := v.Bind("env", envObj); err != nil {
		return err
	}

	if err := v.Bind("sleep", b.sleepFunc()); err != nil {
		return err
	}

	return nil
}

func (b *Bridge) logFunc() func(args ...any) {
	return func(args ...any) {
		if len(args) == 0 {
			b.Log.Logf("")
			return
		}
		// stringify everything; goja passes goja.Value through %v just fine.
		format := ""
		for i := range args {
			if i > 0 {
				format += " "
			}
			format += "%v"
		}
		b.Log.Logf(format, args...)
	}
}

func (b *Bridge) envGet(key string) string {
	return b.Env[key]
}

func (b *Bridge) envKeys() []string {
	keys := make([]string, 0, len(b.Env))
	for k := range b.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (b *Bridge) sleepFunc() func(ms int64) {
	return func(ms int64) {
		if ms <= 0 {
			return
		}
		d := time.Duration(ms) * time.Millisecond
		if d > b.MaxSleep {
			d = b.MaxSleep
		}
		time.Sleep(d)
	}
}
