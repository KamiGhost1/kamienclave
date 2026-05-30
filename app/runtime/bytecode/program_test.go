package bytecode

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"testing"
)

// rawProgram hand-builds a wire image using the identity opcode table,
// so test code can write opcode bytes directly. It deliberately does NOT
// validate — the point is to feed Decode malformed input.
func rawProgram(numLocals int, consts []Value, code []byte) []byte {
	b := []byte{magic0, magic1, magic2, magic3, formatVersion, 0, byte(numLocals)}
	b = binary.BigEndian.AppendUint16(b, uint16(len(consts)))
	for _, c := range consts {
		switch c.Kind {
		case KindNull:
			b = append(b, tagNull)
		case KindBool:
			bb := byte(0)
			if c.b {
				bb = 1
			}
			b = append(b, tagBool, bb)
		case KindNumber:
			b = append(b, tagNumber)
			b = binary.BigEndian.AppendUint64(b, math.Float64bits(c.num))
		case KindString:
			b = append(b, tagString)
			b = binary.BigEndian.AppendUint16(b, uint16(len(c.str)))
			b = append(b, c.str...)
		}
	}
	b = binary.BigEndian.AppendUint32(b, uint32(len(code)))
	return append(b, code...)
}

func TestDecodeRejectsTruncatedOperand(t *testing.T) {
	// OpPushConst needs 2 operand bytes; supply only 1.
	raw := rawProgram(0, []Value{Number(1)}, []byte{byte(OpPushConst), 0x00})
	if _, err := Decode(raw, IdentityTable()); !errors.Is(err, ErrTruncated) {
		t.Fatalf("got %v, want ErrTruncated", err)
	}
}

func TestDecodeRejectsConstIndexOutOfRange(t *testing.T) {
	// No constants, but push index 0.
	raw := rawProgram(0, nil, []byte{byte(OpPushConst), 0x00, 0x00, byte(OpReturn)})
	if _, err := Decode(raw, IdentityTable()); !errors.Is(err, ErrFormat) {
		t.Fatalf("got %v, want ErrFormat", err)
	}
}

func TestDecodeRejectsLocalIndexOutOfRange(t *testing.T) {
	raw := rawProgram(1, nil, []byte{byte(OpLoad), 0x05, byte(OpReturn)})
	if _, err := Decode(raw, IdentityTable()); !errors.Is(err, ErrFormat) {
		t.Fatalf("got %v, want ErrFormat", err)
	}
}

func TestDecodeRejectsJumpIntoInstruction(t *testing.T) {
	// OpJmp at 0 with rel = -2 targets offset 1, the middle of itself.
	code := []byte{byte(OpJmp), 0x00, 0x00, byte(OpHalt)}
	rel := int16(-2)
	binary.BigEndian.PutUint16(code[1:], uint16(rel))
	raw := rawProgram(0, nil, code)
	if _, err := Decode(raw, IdentityTable()); !errors.Is(err, ErrFormat) {
		t.Fatalf("got %v, want ErrFormat", err)
	}
}

func TestDecodeRejectsUnknownOpcode(t *testing.T) {
	raw := rawProgram(0, nil, []byte{0xFE, byte(OpReturn)}) // 0xFE >= numOps
	if _, err := Decode(raw, IdentityTable()); !errors.Is(err, ErrBadOpcode) {
		t.Fatalf("got %v, want ErrBadOpcode", err)
	}
}

// A valid decoded program must never panic at runtime regardless of the
// host table being nil.
func TestRunNilHostsNoPanic(t *testing.T) {
	a := NewAssembler()
	a.PushNumber(1)
	a.Op(OpReturn)
	p, _ := a.Build()
	if _, err := p.Run(context.Background(), nil, Limits{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
