package bytecode

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

// roundTrip encodes the program with a randomised opcode table, decodes
// it back, and asserts the logical code survived the permutation. It
// returns the decoded program so tests exercise the full wire path.
func roundTrip(t *testing.T, p *Program) *Program {
	t.Helper()
	tbl := NewTableFromSeed(0xDEADBEEF)
	raw, err := Encode(p, tbl)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := Decode(raw, tbl)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(got.Code, p.Code) {
		t.Fatalf("code changed across permuted round-trip:\n got %v\nwant %v", got.Code, p.Code)
	}
	return got
}

func runOK(t *testing.T, p *Program, hosts HostTable) Value {
	t.Helper()
	v, err := p.Run(context.Background(), hosts, Limits{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return v
}

func TestArithmeticAndReturn(t *testing.T) {
	a := NewAssembler()
	a.PushNumber(21)
	a.PushNumber(2)
	a.Op(OpMul)
	a.Op(OpReturn)
	p, err := a.Build()
	if err != nil {
		t.Fatal(err)
	}
	v := runOK(t, roundTrip(t, p), nil)
	if v.Kind != KindNumber || v.Num() != 42 {
		t.Fatalf("got %v, want 42", v.Display())
	}
}

func TestStringConcat(t *testing.T) {
	a := NewAssembler()
	a.PushString("foo")
	a.PushNumber(42)
	a.Op(OpAdd) // string + number -> "foo42"
	a.Op(OpReturn)
	p, _ := a.Build()
	v := runOK(t, roundTrip(t, p), nil)
	if v.Kind != KindString || v.Str() != "foo42" {
		t.Fatalf("got %q, want %q", v.Str(), "foo42")
	}
}

func TestLoopWithLocalsAndJumps(t *testing.T) {
	// sum := 0; for i := 1; i <= 5; i++ { sum += i }; return sum  (=15)
	a := NewAssembler()
	const sum, i = 0, 1
	a.PushNumber(0)
	a.Store(sum)
	a.PushNumber(1)
	a.Store(i)

	loop := a.NewLabel()
	end := a.NewLabel()
	a.Bind(loop)
	a.Load(i)
	a.PushNumber(5)
	a.Op(OpLe)
	a.JmpIfFalse(end)
	a.Load(sum)
	a.Load(i)
	a.Op(OpAdd)
	a.Store(sum)
	a.Load(i)
	a.PushNumber(1)
	a.Op(OpAdd)
	a.Store(i)
	a.Jmp(loop)
	a.Bind(end)
	a.Load(sum)
	a.Op(OpReturn)

	p, err := a.Build()
	if err != nil {
		t.Fatal(err)
	}
	v := runOK(t, roundTrip(t, p), nil)
	if v.Num() != 15 {
		t.Fatalf("loop sum = %v, want 15", v.Display())
	}
}

func TestHostCall(t *testing.T) {
	const idTimes10 uint8 = 7
	hosts := HostTable{
		idTimes10: func(args []Value) (Value, error) {
			if len(args) != 1 {
				return Value{}, errors.New("want 1 arg")
			}
			return Number(args[0].Num() * 10), nil
		},
	}
	a := NewAssembler()
	a.PushNumber(4)
	a.HostCall(idTimes10, 1)
	a.Op(OpReturn)
	p, _ := a.Build()
	v := runOK(t, roundTrip(t, p), hosts)
	if v.Num() != 40 {
		t.Fatalf("hostcall result = %v, want 40", v.Display())
	}
}

func TestHostCallArgOrder(t *testing.T) {
	// Ensure args arrive in source/push order: first pushed is args[0].
	const idSub uint8 = 1
	hosts := HostTable{
		idSub: func(args []Value) (Value, error) {
			return Number(args[0].Num() - args[1].Num()), nil
		},
	}
	a := NewAssembler()
	a.PushNumber(10)
	a.PushNumber(3)
	a.HostCall(idSub, 2)
	a.Op(OpReturn)
	p, _ := a.Build()
	if v := runOK(t, p, hosts); v.Num() != 7 {
		t.Fatalf("arg order wrong: got %v, want 7", v.Display())
	}
}

func TestUnknownHostIsError(t *testing.T) {
	a := NewAssembler()
	a.PushNumber(1)
	a.HostCall(99, 1)
	a.Op(OpReturn)
	p, _ := a.Build()
	if _, err := p.Run(context.Background(), nil, Limits{}); !errors.Is(err, ErrUnknownHost) {
		t.Fatalf("got %v, want ErrUnknownHost", err)
	}
}

func TestComparisonsAndNot(t *testing.T) {
	cases := []struct {
		build func(*Assembler)
		want  bool
	}{
		{func(a *Assembler) { a.PushNumber(1); a.PushNumber(2); a.Op(OpLt) }, true},
		{func(a *Assembler) { a.PushNumber(2); a.PushNumber(2); a.Op(OpGe) }, true},
		{func(a *Assembler) { a.PushString("a"); a.PushString("b"); a.Op(OpGt) }, false},
		{func(a *Assembler) { a.PushBool(false); a.Op(OpNot) }, true},
		{func(a *Assembler) { a.PushNumber(1); a.PushNumber(1); a.Op(OpEq) }, true},
	}
	for i, c := range cases {
		a := NewAssembler()
		c.build(a)
		a.Op(OpReturn)
		p, err := a.Build()
		if err != nil {
			t.Fatalf("case %d build: %v", i, err)
		}
		v := runOK(t, p, nil)
		if v.Kind != KindBool || v.B() != c.want {
			t.Fatalf("case %d: got %v, want %v", i, v.Display(), c.want)
		}
	}
}

func TestArrayOpcodes(t *testing.T) {
	// a := [1,2,3]; a[1] = 99; return a[1] + len(a)  => 99 + 3 = 102
	a := NewAssembler()
	a.PushNumber(1)
	a.PushNumber(2)
	a.PushNumber(3)
	a.NewArray(3)
	a.Store(0)

	a.Load(0)
	a.PushNumber(1)
	a.PushNumber(99)
	a.Op(OpIndexSet)
	a.Op(OpPop) // discard the value IndexSet leaves

	a.Load(0)
	a.PushNumber(1)
	a.Op(OpIndexGet) // 99
	a.Load(0)
	a.Op(OpLen) // 3
	a.Op(OpAdd) // 102
	a.Op(OpReturn)

	p, err := a.Build()
	if err != nil {
		t.Fatal(err)
	}
	if v := runOK(t, roundTrip(t, p), nil); v.Num() != 102 {
		t.Fatalf("array ops = %v, want 102", v.Display())
	}
}

func TestObjectOpcodes(t *testing.T) {
	// o := {"a":1}; o["b"] = o["a"] + 41; return o["a"] + o["b"]  => 1 + 42 = 43
	a := NewAssembler()
	a.PushString("a")
	a.PushNumber(1)
	a.NewObject(1)
	a.Store(0)

	a.Load(0)
	a.PushString("b")
	a.Load(0)
	a.PushString("a")
	a.Op(OpIndexGet) // 1
	a.PushNumber(41)
	a.Op(OpAdd) // 42
	a.Op(OpIndexSet)
	a.Op(OpPop)

	a.Load(0)
	a.PushString("a")
	a.Op(OpIndexGet)
	a.Load(0)
	a.PushString("b")
	a.Op(OpIndexGet)
	a.Op(OpAdd)
	a.Op(OpReturn)

	p, err := a.Build()
	if err != nil {
		t.Fatal(err)
	}
	if v := runOK(t, roundTrip(t, p), nil); v.Num() != 43 {
		t.Fatalf("object ops = %v, want 43", v.Display())
	}
}

func TestObjectMissingKeyIsNull(t *testing.T) {
	a := NewAssembler()
	a.NewObject(0)
	a.PushString("nope")
	a.Op(OpIndexGet)
	a.Op(OpReturn)
	p, _ := a.Build()
	if v := runOK(t, p, nil); v.Kind != KindNull {
		t.Fatalf("missing key = %v, want null", v.Display())
	}
}

func TestIndexGetOutOfRangeIsNull(t *testing.T) {
	a := NewAssembler()
	a.PushNumber(1)
	a.NewArray(1)
	a.PushNumber(5) // out of range
	a.Op(OpIndexGet)
	a.Op(OpReturn)
	p, _ := a.Build()
	if v := runOK(t, p, nil); v.Kind != KindNull {
		t.Fatalf("oob index = %v, want null", v.Display())
	}
}

func TestStepLimit(t *testing.T) {
	// Infinite loop: while(true) {}
	a := NewAssembler()
	loop := a.NewLabel()
	a.Bind(loop)
	a.Jmp(loop)
	p, _ := a.Build()
	if _, err := p.Run(context.Background(), nil, Limits{MaxSteps: 1000}); !errors.Is(err, ErrStepLimit) {
		t.Fatalf("got %v, want ErrStepLimit", err)
	}
}

func TestContextCancel(t *testing.T) {
	a := NewAssembler()
	loop := a.NewLabel()
	a.Bind(loop)
	a.Jmp(loop)
	p, _ := a.Build()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := p.Run(ctx, nil, Limits{MaxSteps: 1 << 30}); !errors.Is(err, ErrInterrupted) {
		t.Fatalf("got %v, want ErrInterrupted", err)
	}
}

func TestTypeErrorOnBadArithmetic(t *testing.T) {
	a := NewAssembler()
	a.PushBool(true)
	a.PushNumber(1)
	a.Op(OpSub)
	a.Op(OpReturn)
	p, _ := a.Build()
	if _, err := p.Run(context.Background(), nil, Limits{}); !errors.Is(err, ErrType) {
		t.Fatalf("got %v, want ErrType", err)
	}
}

func TestDecodeRejectsBadMagic(t *testing.T) {
	if _, err := Decode([]byte("XXXX\x01\x00\x00"), IdentityTable()); !errors.Is(err, ErrFormat) {
		t.Fatalf("got %v, want ErrFormat", err)
	}
}

func TestDecodeRejectsWrongTable(t *testing.T) {
	// Encoding with one permutation and decoding with another must not
	// silently produce a valid program (it should hit an unknown opcode
	// or a validation failure).
	a := NewAssembler()
	a.PushNumber(1)
	a.Op(OpReturn)
	p, _ := a.Build()
	raw, err := Encode(p, NewTableFromSeed(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(raw, NewTableFromSeed(2)); err == nil {
		t.Fatal("decode with mismatched table should fail")
	}
}
