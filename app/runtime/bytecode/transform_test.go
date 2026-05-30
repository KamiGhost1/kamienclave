package bytecode

import (
	"context"
	"errors"
	"testing"
)

func progAB(t *testing.T) *Program {
	t.Helper()
	a := NewAssembler()
	a.PushString("a")
	a.PushString("b")
	a.Op(OpAdd) // "ab"
	a.Op(OpReturn)
	p, err := a.Build()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestInsertConstantsPreservesBehaviour(t *testing.T) {
	p := progAB(t)
	extra := []Value{Number(111), String("zzz")}
	np, err := p.InsertConstants(extra, []int{0, 2})
	if err != nil {
		t.Fatalf("InsertConstants: %v", err)
	}
	if len(np.Consts) != len(p.Consts)+2 {
		t.Fatalf("const count = %d, want %d", len(np.Consts), len(p.Consts)+2)
	}
	// Behaviour unchanged despite shifted indices.
	v, err := np.Run(context.Background(), nil, Limits{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if v.Str() != "ab" {
		t.Fatalf("got %q, want ab", v.Str())
	}
	// Extra constants are present.
	var sawNum, sawStr bool
	for _, c := range np.Constants() {
		if c.Kind == KindNumber && c.Num() == 111 {
			sawNum = true
		}
		if c.Kind == KindString && c.Str() == "zzz" {
			sawStr = true
		}
	}
	if !sawNum || !sawStr {
		t.Fatalf("inserted constants missing: num=%v str=%v", sawNum, sawStr)
	}
}

func TestInsertConstantsRejectsBadPositions(t *testing.T) {
	p := progAB(t)
	// duplicate position
	if _, err := p.InsertConstants([]Value{Null(), Null()}, []int{1, 1}); !errors.Is(err, ErrFormat) {
		t.Fatalf("duplicate pos: got %v, want ErrFormat", err)
	}
	// out of range
	if _, err := p.InsertConstants([]Value{Null()}, []int{99}); !errors.Is(err, ErrFormat) {
		t.Fatalf("oor pos: got %v, want ErrFormat", err)
	}
	// length mismatch
	if _, err := p.InsertConstants([]Value{Null()}, []int{0, 1}); !errors.Is(err, ErrFormat) {
		t.Fatalf("len mismatch: got %v, want ErrFormat", err)
	}
}
