package bytecode

import (
	"encoding/binary"
	"fmt"
)

// InsertConstants returns a copy of p with extra constants spliced into
// the constant pool at the given final indices, remapping every
// OpPushConst operand so the program's behaviour is unchanged.
//
// It is an ISA-level transform (it must understand opcode operands), so
// it lives with the VM. Its primary use is server-side watermarking
// (TECHNICAL.md §8.4.1): inert fingerprint constants are spread through
// the pool rather than appended in one removable block.
//
// at[i] is the index extra[i] will occupy in the new pool; the indices
// must be distinct and within [0, len(p.Consts)+len(extra)). The
// original constants keep their relative order in the remaining slots.
func (p *Program) InsertConstants(extra []Value, at []int) (*Program, error) {
	if len(extra) != len(at) {
		return nil, fmt.Errorf("%w: extra/positions length mismatch", ErrFormat)
	}
	total := len(p.Consts) + len(extra)
	occupied := make([]bool, total)
	newConsts := make([]Value, total)
	for i, pos := range at {
		if pos < 0 || pos >= total || occupied[pos] {
			return nil, fmt.Errorf("%w: bad insertion position %d", ErrFormat, pos)
		}
		occupied[pos] = true
		newConsts[pos] = extra[i]
	}

	// Place the originals into the free slots in order, recording the
	// old->new index mapping for operand rewriting.
	remap := make([]int, len(p.Consts))
	next := 0
	for old := range p.Consts {
		for occupied[next] {
			next++
		}
		newConsts[next] = p.Consts[old]
		remap[old] = next
		occupied[next] = true
		next++
	}

	code := make([]byte, len(p.Code))
	copy(code, p.Code)
	for i := 0; i < len(code); {
		op := Op(code[i])
		if !op.valid() {
			return nil, ErrBadOpcode
		}
		w := operandWidth(op)
		if i+1+w > len(code) {
			return nil, ErrTruncated
		}
		if op == OpPushConst {
			old := int(binary.BigEndian.Uint16(code[i+1 : i+3]))
			if old >= len(remap) {
				return nil, fmt.Errorf("%w: const index out of range", ErrFormat)
			}
			binary.BigEndian.PutUint16(code[i+1:i+3], uint16(remap[old]))
		}
		i += 1 + w
	}

	np := &Program{NumLocals: p.NumLocals, Consts: newConsts, Code: code}
	if err := np.validate(); err != nil {
		return nil, err
	}
	return np, nil
}

// Constants exposes the constant pool read-only (a copy) for tooling such
// as watermark extraction that inspects literals without executing code.
func (p *Program) Constants() []Value {
	out := make([]Value, len(p.Consts))
	copy(out, p.Consts)
	return out
}
