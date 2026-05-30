package bytecode

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

var (
	ErrStackUnderflow = errors.New("bytecode: stack underflow")
	ErrStackOverflow  = errors.New("bytecode: stack overflow")
	ErrType           = errors.New("bytecode: type error")
	ErrUnknownHost    = errors.New("bytecode: unknown host function")
	ErrStepLimit      = errors.New("bytecode: step limit exceeded")
	ErrInterrupted    = errors.New("bytecode: execution interrupted")
)

// HostFunc is a single whitelisted host primitive. Arguments arrive in
// source order (args[0] is the first pushed). The bridge that builds the
// table is the sole audit point for what the payload can reach
// (TECHNICAL.md §7.2.1).
type HostFunc func(args []Value) (Value, error)

// HostTable maps host-call ids to functions. Ids are part of the ABI
// contract; an unmapped id is a hard error, never a silent no-op.
type HostTable map[uint8]HostFunc

// Limits bound a single execution. Zero fields fall back to defaults so
// callers can pass the zero value for "reasonable bounds".
type Limits struct {
	MaxSteps int // instructions executed before ErrStepLimit; default 1<<24
	MaxStack int // operand stack depth; default 1024
}

const (
	defaultMaxSteps = 1 << 24
	defaultMaxStack = 1024
	ctxCheckEvery   = 4096 // check ctx cancellation every N steps
)

// Run executes p against the supplied host table and returns the
// completion value (the operand of OpReturn, or null if the program
// halts or falls off the end). The program is assumed to have passed
// validate() during Decode; programs built in-process should be encoded
// and decoded, or call validate via Decode, before Run.
func (p *Program) Run(ctx context.Context, hosts HostTable, lim Limits) (Value, error) {
	if lim.MaxSteps <= 0 {
		lim.MaxSteps = defaultMaxSteps
	}
	if lim.MaxStack <= 0 {
		lim.MaxStack = defaultMaxStack
	}

	stack := make([]Value, 0, 16)
	locals := make([]Value, p.NumLocals)
	for i := range locals {
		locals[i] = Null()
	}

	push := func(v Value) error {
		if len(stack) >= lim.MaxStack {
			return ErrStackOverflow
		}
		stack = append(stack, v)
		return nil
	}
	pop := func() (Value, error) {
		if len(stack) == 0 {
			return Value{}, ErrStackUnderflow
		}
		v := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		return v, nil
	}

	steps := 0
	for pc := 0; pc < len(p.Code); {
		if steps++; steps > lim.MaxSteps {
			return Value{}, ErrStepLimit
		}
		if steps%ctxCheckEvery == 0 {
			if err := ctx.Err(); err != nil {
				return Value{}, ErrInterrupted
			}
		}

		op := Op(p.Code[pc])
		operand := pc + 1
		pc += 1 + operandWidth(op)

		switch op {
		case OpNop:
			// nothing

		case OpPushConst:
			idx := binary.BigEndian.Uint16(p.Code[operand : operand+2])
			if err := push(p.Consts[idx]); err != nil {
				return Value{}, err
			}

		case OpPop:
			if _, err := pop(); err != nil {
				return Value{}, err
			}

		case OpDup:
			if len(stack) == 0 {
				return Value{}, ErrStackUnderflow
			}
			if err := push(stack[len(stack)-1]); err != nil {
				return Value{}, err
			}

		case OpLoad:
			if err := push(locals[p.Code[operand]]); err != nil {
				return Value{}, err
			}

		case OpStore:
			v, err := pop()
			if err != nil {
				return Value{}, err
			}
			locals[p.Code[operand]] = v

		case OpAdd, OpSub, OpMul, OpDiv, OpMod:
			b, err := pop()
			if err != nil {
				return Value{}, err
			}
			a, err := pop()
			if err != nil {
				return Value{}, err
			}
			res, err := arith(op, a, b)
			if err != nil {
				return Value{}, err
			}
			if err := push(res); err != nil {
				return Value{}, err
			}

		case OpNeg:
			a, err := pop()
			if err != nil {
				return Value{}, err
			}
			if a.Kind != KindNumber {
				return Value{}, fmt.Errorf("%w: neg on non-number", ErrType)
			}
			if err := push(Number(-a.num)); err != nil {
				return Value{}, err
			}

		case OpEq, OpNe:
			b, err := pop()
			if err != nil {
				return Value{}, err
			}
			a, err := pop()
			if err != nil {
				return Value{}, err
			}
			eq := a.Equal(b)
			if op == OpNe {
				eq = !eq
			}
			if err := push(Bool(eq)); err != nil {
				return Value{}, err
			}

		case OpLt, OpLe, OpGt, OpGe:
			b, err := pop()
			if err != nil {
				return Value{}, err
			}
			a, err := pop()
			if err != nil {
				return Value{}, err
			}
			res, err := compare(op, a, b)
			if err != nil {
				return Value{}, err
			}
			if err := push(Bool(res)); err != nil {
				return Value{}, err
			}

		case OpNot:
			a, err := pop()
			if err != nil {
				return Value{}, err
			}
			if err := push(Bool(!a.Truthy())); err != nil {
				return Value{}, err
			}

		case OpJmp:
			rel := int(int16(binary.BigEndian.Uint16(p.Code[operand : operand+2])))
			pc += rel

		case OpJmpIfFalse:
			rel := int(int16(binary.BigEndian.Uint16(p.Code[operand : operand+2])))
			v, err := pop()
			if err != nil {
				return Value{}, err
			}
			if !v.Truthy() {
				pc += rel
			}

		case OpHostCall:
			id := p.Code[operand]
			argc := int(p.Code[operand+1])
			if len(stack) < argc {
				return Value{}, ErrStackUnderflow
			}
			fn, ok := hosts[id]
			if !ok {
				return Value{}, fmt.Errorf("%w: id %d", ErrUnknownHost, id)
			}
			args := make([]Value, argc)
			copy(args, stack[len(stack)-argc:])
			stack = stack[:len(stack)-argc]
			res, err := fn(args)
			if err != nil {
				return Value{}, fmt.Errorf("bytecode: host %d: %w", id, err)
			}
			if err := push(res); err != nil {
				return Value{}, err
			}

		case OpReturn:
			if len(stack) == 0 {
				return Null(), nil // empty stack -> null completion
			}
			v, _ := pop()
			return v, nil

		case OpHalt:
			return Null(), nil

		case OpNewArray:
			n := int(binary.BigEndian.Uint16(p.Code[operand : operand+2]))
			if len(stack) < n {
				return Value{}, ErrStackUnderflow
			}
			elems := make([]Value, n)
			copy(elems, stack[len(stack)-n:])
			stack = stack[:len(stack)-n]
			if err := push(Array(elems)); err != nil {
				return Value{}, err
			}

		case OpIndexGet:
			idx, err := pop()
			if err != nil {
				return Value{}, err
			}
			coll, err := pop()
			if err != nil {
				return Value{}, err
			}
			res, err := indexGet(coll, idx)
			if err != nil {
				return Value{}, err
			}
			if err := push(res); err != nil {
				return Value{}, err
			}

		case OpIndexSet:
			val, err := pop()
			if err != nil {
				return Value{}, err
			}
			idx, err := pop()
			if err != nil {
				return Value{}, err
			}
			arr, err := pop()
			if err != nil {
				return Value{}, err
			}
			if err := indexSet(arr, idx, val); err != nil {
				return Value{}, err
			}
			if err := push(val); err != nil {
				return Value{}, err
			}

		case OpNewObject:
			n := int(binary.BigEndian.Uint16(p.Code[operand : operand+2]))
			if len(stack) < 2*n {
				return Value{}, ErrStackUnderflow
			}
			m := make(map[string]Value, n)
			base := len(stack) - 2*n
			for i := 0; i < n; i++ {
				k := stack[base+2*i]
				v := stack[base+2*i+1]
				if k.Kind != KindString {
					return Value{}, fmt.Errorf("%w: object key must be a string", ErrType)
				}
				m[k.str] = v
			}
			stack = stack[:base]
			if err := push(Object(m)); err != nil {
				return Value{}, err
			}

		case OpLen:
			v, err := pop()
			if err != nil {
				return Value{}, err
			}
			switch v.Kind {
			case KindArray:
				if err := push(Number(float64(len(v.Elems())))); err != nil {
					return Value{}, err
				}
			case KindString:
				if err := push(Number(float64(len(v.str)))); err != nil {
					return Value{}, err
				}
			default:
				return Value{}, fmt.Errorf("%w: length of non-array/string", ErrType)
			}

		default:
			return Value{}, ErrBadOpcode
		}
	}
	return Null(), nil
}

func arith(op Op, a, b Value) (Value, error) {
	// String concatenation is only defined for OpAdd when either side is
	// a string; everything else requires two numbers.
	if op == OpAdd && (a.Kind == KindString || b.Kind == KindString) {
		return String(a.Display() + b.Display()), nil
	}
	if a.Kind != KindNumber || b.Kind != KindNumber {
		return Value{}, fmt.Errorf("%w: arithmetic on non-number", ErrType)
	}
	switch op {
	case OpAdd:
		return Number(a.num + b.num), nil
	case OpSub:
		return Number(a.num - b.num), nil
	case OpMul:
		return Number(a.num * b.num), nil
	case OpDiv:
		return Number(a.num / b.num), nil
	case OpMod:
		return Number(math.Mod(a.num, b.num)), nil
	default:
		return Value{}, ErrBadOpcode
	}
}

func compare(op Op, a, b Value) (bool, error) {
	switch {
	case a.Kind == KindNumber && b.Kind == KindNumber:
		return cmpOrdered(op, a.num > b.num, a.num < b.num, a.num == b.num), nil
	case a.Kind == KindString && b.Kind == KindString:
		return cmpOrdered(op, a.str > b.str, a.str < b.str, a.str == b.str), nil
	default:
		return false, fmt.Errorf("%w: ordered comparison of mismatched kinds", ErrType)
	}
}

// indexGet reads coll[idx] for an array (out-of-range -> null) or a
// string (out-of-range -> empty string).
func indexGet(coll, idx Value) (Value, error) {
	// Objects are keyed by string; arrays/strings by number.
	if coll.Kind == KindObject {
		if idx.Kind != KindString {
			return Value{}, fmt.Errorf("%w: object key must be a string", ErrType)
		}
		if v, ok := coll.Props()[idx.str]; ok {
			return v, nil
		}
		return Null(), nil // missing property -> null (JS undefined)
	}
	if idx.Kind != KindNumber {
		return Value{}, fmt.Errorf("%w: index must be a number", ErrType)
	}
	i := int(idx.num)
	switch coll.Kind {
	case KindArray:
		els := coll.Elems()
		if i < 0 || i >= len(els) {
			return Null(), nil
		}
		return els[i], nil
	case KindString:
		if i < 0 || i >= len(coll.str) {
			return String(""), nil
		}
		return String(coll.str[i : i+1]), nil
	default:
		return Value{}, fmt.Errorf("%w: indexing non-array/string/object", ErrType)
	}
}

// indexSet writes arr[idx]=val, growing the array with nulls if idx is
// past the end (JS-like). Only arrays are mutable.
func indexSet(arr, idx, val Value) error {
	if arr.Kind == KindObject {
		if idx.Kind != KindString {
			return fmt.Errorf("%w: object key must be a string", ErrType)
		}
		if arr.obj == nil {
			return fmt.Errorf("%w: nil object", ErrType)
		}
		(*arr.obj)[idx.str] = val
		return nil
	}
	if arr.Kind != KindArray || arr.arr == nil {
		return fmt.Errorf("%w: index-assign to non-array/object", ErrType)
	}
	if idx.Kind != KindNumber {
		return fmt.Errorf("%w: index must be a number", ErrType)
	}
	i := int(idx.num)
	if i < 0 {
		return fmt.Errorf("%w: negative index", ErrType)
	}
	s := *arr.arr
	if i >= len(s) {
		grown := make([]Value, i+1)
		copy(grown, s)
		for j := len(s); j <= i; j++ {
			grown[j] = Null()
		}
		*arr.arr = grown
		s = grown
	}
	s[i] = val
	return nil
}

func cmpOrdered(op Op, gt, lt, eq bool) bool {
	switch op {
	case OpLt:
		return lt
	case OpLe:
		return lt || eq
	case OpGt:
		return gt
	case OpGe:
		return gt || eq
	default:
		return false
	}
}
