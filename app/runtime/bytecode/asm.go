package bytecode

import (
	"encoding/binary"
	"fmt"
)

// Assembler is a small builder for constructing Programs by hand. It is
// the reference encoder used by tests and by any local tooling that
// needs to feed the VM without the server-side compiler. It is NOT the
// production frontend — that compiles a source language to this same
// instruction set inside kamienclave-server.
//
// Jumps are expressed with labels; relative offsets are resolved in
// Build, matching the VM's "pc has already advanced past the operand"
// convention.
type Assembler struct {
	consts   []Value
	constIdx map[Value]int
	code     []byte
	labels   []int   // label id -> code position (-1 until bound)
	patches  []patch // unresolved jump operands
	locals   int
}

type patch struct {
	operandAt int // index in code of the 2-byte relative operand
	base      int // pc value the relative offset is added to
	label     Label
}

// Label is an opaque jump target handle.
type Label int

// NewAssembler returns an empty assembler.
func NewAssembler() *Assembler {
	return &Assembler{constIdx: map[Value]int{}}
}

// Const interns v and returns its constant-pool index.
func (a *Assembler) Const(v Value) int {
	if i, ok := a.constIdx[v]; ok {
		return i
	}
	i := len(a.consts)
	a.consts = append(a.consts, v)
	a.constIdx[v] = i
	return i
}

func (a *Assembler) op(op Op) { a.code = append(a.code, byte(op)) }

// Op emits a zero-operand instruction (arithmetic, comparisons, stack
// ops, Return, Halt, ...).
func (a *Assembler) Op(op Op) {
	if operandWidth(op) != 0 {
		panic(fmt.Sprintf("bytecode: Op called with operand-carrying opcode %d", op))
	}
	a.op(op)
}

// PushConst emits a push of v (interning the constant).
func (a *Assembler) PushConst(v Value) {
	idx := a.Const(v)
	a.op(OpPushConst)
	a.code = binary.BigEndian.AppendUint16(a.code, uint16(idx))
}

// Convenience wrappers around PushConst.
func (a *Assembler) PushNumber(f float64) { a.PushConst(Number(f)) }
func (a *Assembler) PushString(s string)  { a.PushConst(String(s)) }
func (a *Assembler) PushBool(b bool)      { a.PushConst(Bool(b)) }
func (a *Assembler) PushNull()            { a.PushConst(Null()) }

// Load / Store address a local slot, growing the declared local count.
func (a *Assembler) Load(slot int)  { a.slotOp(OpLoad, slot) }
func (a *Assembler) Store(slot int) { a.slotOp(OpStore, slot) }

func (a *Assembler) slotOp(op Op, slot int) {
	if slot < 0 || slot > 255 {
		panic("bytecode: local slot out of range")
	}
	if slot+1 > a.locals {
		a.locals = slot + 1
	}
	a.op(op)
	a.code = append(a.code, byte(slot))
}

// HostCall emits a call to host function id with argc arguments.
func (a *Assembler) HostCall(id uint8, argc uint8) {
	a.op(OpHostCall)
	a.code = append(a.code, id, argc)
}

// NewArray emits construction of an array from the top n stack values.
func (a *Assembler) NewArray(n int) {
	if n < 0 || n > 65535 {
		panic("bytecode: array literal too large")
	}
	a.op(OpNewArray)
	a.code = binary.BigEndian.AppendUint16(a.code, uint16(n))
}

// NewObject emits construction of an object from the top n key/value
// pairs (2*n stack values, key then value for each).
func (a *Assembler) NewObject(n int) {
	if n < 0 || n > 65535 {
		panic("bytecode: object literal too large")
	}
	a.op(OpNewObject)
	a.code = binary.BigEndian.AppendUint16(a.code, uint16(n))
}

// NewLabel allocates an unbound label.
func (a *Assembler) NewLabel() Label {
	a.labels = append(a.labels, -1)
	return Label(len(a.labels) - 1)
}

// Bind fixes l to the current code position.
func (a *Assembler) Bind(l Label) {
	a.labels[l] = len(a.code)
}

// Jmp / JmpIfFalse emit a jump to l, recording a patch to resolve later.
func (a *Assembler) Jmp(l Label)        { a.jump(OpJmp, l) }
func (a *Assembler) JmpIfFalse(l Label) { a.jump(OpJmpIfFalse, l) }

func (a *Assembler) jump(op Op, l Label) {
	a.op(op)
	operandAt := len(a.code)
	a.code = append(a.code, 0, 0) // placeholder
	// base = pc after this instruction (op byte + 2 operand bytes).
	a.patches = append(a.patches, patch{operandAt: operandAt, base: operandAt + 2, label: l})
}

// Build resolves jumps and returns a validated Program.
func (a *Assembler) Build() (*Program, error) {
	for _, p := range a.patches {
		target := a.labels[p.label]
		if target < 0 {
			return nil, fmt.Errorf("bytecode: unbound label %d", p.label)
		}
		rel := target - p.base
		if rel < -32768 || rel > 32767 {
			return nil, fmt.Errorf("bytecode: jump out of int16 range")
		}
		binary.BigEndian.PutUint16(a.code[p.operandAt:], uint16(int16(rel)))
	}
	prog := &Program{
		NumLocals: a.locals,
		Consts:    a.consts,
		Code:      a.code,
	}
	if err := prog.validate(); err != nil {
		return nil, err
	}
	return prog, nil
}
