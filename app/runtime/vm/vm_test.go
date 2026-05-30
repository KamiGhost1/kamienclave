package vm

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunReturnsValue(t *testing.T) {
	v := New(Options{})
	defer v.Close()

	src := []byte(`2 + 3`)
	got, err := v.Run(context.Background(), "test.js", src)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got == nil || got.ToInteger() != 5 {
		t.Fatalf("got %v, want 5", got)
	}
}

func TestRunWipesSource(t *testing.T) {
	v := New(Options{})
	defer v.Close()

	src := []byte(`"hello"`)
	want := append([]byte(nil), src...)

	if _, err := v.Run(context.Background(), "x.js", src); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Source buffer should be zeroised after Run returns.
	for i, b := range src {
		if b != 0 {
			t.Fatalf("byte %d not wiped (want zero, got %d); original was %q", i, b, want)
		}
	}
}

func TestRunHonoursContext(t *testing.T) {
	v := New(Options{})
	defer v.Close()

	// Spin-loop in JS — only the interrupt can stop it.
	src := []byte(`while (true) { /* busy */ }`)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := v.Run(ctx, "spin.js", src)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrInterrupted) {
		t.Fatalf("got err %v, want ErrInterrupted", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Run took too long to interrupt: %v", elapsed)
	}
}

func TestBindHostFunction(t *testing.T) {
	v := New(Options{})
	defer v.Close()

	var counter atomic.Int32
	if err := v.Bind("inc", func() { counter.Add(1) }); err != nil {
		t.Fatalf("Bind: %v", err)
	}

	src := []byte(`inc(); inc(); inc(); "ok"`)
	val, err := v.Run(context.Background(), "bind.js", src)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if val.String() != "ok" {
		t.Fatalf("unexpected val: %v", val)
	}
	if counter.Load() != 3 {
		t.Fatalf("counter = %d, want 3", counter.Load())
	}
}

func TestRunRejectsCompileError(t *testing.T) {
	v := New(Options{})
	defer v.Close()

	src := []byte(`this is not valid js`)
	_, err := v.Run(context.Background(), "broken.js", src)
	if err == nil {
		t.Fatal("expected compile error")
	}
	if !strings.Contains(err.Error(), "compile") {
		t.Fatalf("error doesn't mention compile stage: %v", err)
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	v := New(Options{})
	v.Close()
	v.Close()
	if _, err := v.Run(context.Background(), "x", []byte("1")); err == nil {
		t.Fatal("Run after Close should fail")
	}
}

func TestNoFileSystemAccess(t *testing.T) {
	v := New(Options{})
	defer v.Close()

	// goja by default has no require/fs/process — verify by trying.
	for _, expr := range []string{
		`typeof require`,
		`typeof process`,
		`typeof fs`,
		`typeof Buffer`,
	} {
		src := []byte(expr)
		got, err := v.Run(context.Background(), "probe.js", src)
		if err != nil {
			t.Fatalf("probe %q: %v", expr, err)
		}
		if got.String() != "undefined" {
			t.Fatalf("%q = %q, want undefined", expr, got.String())
		}
		// re-create — Run consumed the buffer
		v.Close()
		v = New(Options{})
	}
}
