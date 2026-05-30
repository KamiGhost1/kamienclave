package bytecode

import (
	"context"
	"testing"
)

// FuzzDecode feeds arbitrary bytes to the wire decoder. Decode parses
// data that arrives over the network (the AEAD-decrypted payload), so it
// must never panic, hang, or read out of bounds on malformed input — it
// may only return an error or a valid Program.
func FuzzDecode(f *testing.F) {
	tbl := IdentityTable()

	// Seed corpus: a few well-formed programs plus degenerate inputs.
	seedPrograms := []func(*Assembler){
		func(a *Assembler) { a.PushNumber(42); a.Op(OpReturn) },
		func(a *Assembler) {
			a.PushString("x")
			a.PushString("y")
			a.Op(OpAdd)
			a.Op(OpReturn)
		},
		func(a *Assembler) {
			loop := a.NewLabel()
			end := a.NewLabel()
			a.PushNumber(0)
			a.Store(0)
			a.Bind(loop)
			a.Load(0)
			a.PushNumber(3)
			a.Op(OpLt)
			a.JmpIfFalse(end)
			a.Load(0)
			a.PushNumber(1)
			a.Op(OpAdd)
			a.Store(0)
			a.Jmp(loop)
			a.Bind(end)
			a.Load(0)
			a.Op(OpReturn)
		},
	}
	for _, build := range seedPrograms {
		a := NewAssembler()
		build(a)
		if p, err := a.Build(); err == nil {
			if raw, err := Encode(p, tbl); err == nil {
				f.Add(raw)
			}
		}
	}
	f.Add([]byte{})
	f.Add([]byte("DLBC"))
	f.Add(make([]byte, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic regardless of input.
		prog, err := Decode(data, tbl)
		if err != nil {
			return // rejected cleanly — fine
		}
		// A program that decoded must also run without panicking under a
		// tight step budget (it may error; it must not crash the VM).
		ctx := context.Background()
		_, _ = prog.Run(ctx, nil, Limits{MaxSteps: 100_000, MaxStack: 256})
	})
}

// FuzzDecodeEncrypted exercises the encrypted-pool decode path with a
// fixed key, ensuring the decryptor handles arbitrary ciphertext shapes
// without panicking.
func FuzzDecodeEncrypted(f *testing.F) {
	tbl := IdentityTable()
	key := make([]byte, ConstKeySize)
	for i := range key {
		key[i] = byte(i)
	}

	a := NewAssembler()
	a.PushString("secret")
	a.PushNumber(1)
	a.Op(OpAdd)
	a.Op(OpReturn)
	if p, err := a.Build(); err == nil {
		if raw, err := EncodeEncrypted(p, tbl, key); err == nil {
			f.Add(raw)
		}
	}
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		prog, err := DecodeEncrypted(data, tbl, key)
		if err != nil {
			return
		}
		_, _ = prog.Run(context.Background(), nil, Limits{MaxSteps: 100_000, MaxStack: 256})
	})
}
