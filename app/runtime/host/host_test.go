package host

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/KamiGhost1/kamienclave/runtime/vm"
)

func newVMWithHost(t *testing.T, b *Bridge) *vm.VM {
	t.Helper()
	v := vm.New(vm.Options{})
	if err := b.Install(v); err != nil {
		t.Fatalf("Install: %v", err)
	}
	return v
}

func TestLogWrites(t *testing.T) {
	var buf bytes.Buffer
	b := New()
	b.Log = WriterLogger{W: &buf}

	v := newVMWithHost(t, b)
	defer v.Close()

	src := []byte(`log("hello", 42); "ok"`)
	if _, err := v.Run(context.Background(), "log.js", src); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(buf.String(), "hello") || !strings.Contains(buf.String(), "42") {
		t.Fatalf("log output missing pieces: %q", buf.String())
	}
}

func TestEnvGetReturnsWhitelistedOnly(t *testing.T) {
	b := New()
	b.Env = map[string]string{"FOO": "bar"}

	v := newVMWithHost(t, b)
	defer v.Close()

	src := []byte(`env.get("FOO") + ":" + env.get("MISSING")`)
	val, err := v.Run(context.Background(), "env.js", src)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if val.String() != "bar:" {
		t.Fatalf("got %q, want %q", val.String(), "bar:")
	}
}

func TestEnvKeysSorted(t *testing.T) {
	b := New()
	b.Env = map[string]string{"B": "2", "A": "1", "C": "3"}

	v := newVMWithHost(t, b)
	defer v.Close()

	src := []byte(`env.keys().join(",")`)
	val, err := v.Run(context.Background(), "envkeys.js", src)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if val.String() != "A,B,C" {
		t.Fatalf("got %q, want A,B,C", val.String())
	}
}

func TestSleepCapped(t *testing.T) {
	b := New()
	b.MaxSleep = 20 * time.Millisecond

	v := newVMWithHost(t, b)
	defer v.Close()

	src := []byte(`sleep(5000); "done"`) // asks for 5s, cap is 20ms
	start := time.Now()
	val, err := v.Run(context.Background(), "sleep.js", src)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if val.String() != "done" {
		t.Fatalf("val = %v", val)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("sleep cap not enforced: elapsed = %v", elapsed)
	}
}

func TestNoForbiddenGlobals(t *testing.T) {
	b := New()
	v := newVMWithHost(t, b)
	defer v.Close()

	// Even after the host bridge is installed, forbidden globals stay
	// undefined. This is the guarantee we promise the payload author.
	src := []byte(`[typeof require, typeof process, typeof fs, typeof globalThis.require].join(",")`)
	val, err := v.Run(context.Background(), "probe.js", src)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if val.String() != "undefined,undefined,undefined,undefined" {
		t.Fatalf("forbidden globals leaked: %q", val.String())
	}
}
