// Package bytecode implements kamienclave's in-memory mini-VM: a small,
// versioned stack machine that executes a custom bytecode format instead
// of readable JavaScript (TECHNICAL.md §7.1).
//
// Rationale (draft 0.2): handing a readable JS source string to an
// embedded interpreter is the weakest point of an in-memory protection
// scheme — an attacker hooks the compile entry point and lifts the
// source in one piece. By compiling server-side to an opaque bytecode
// and executing it here, a memory dump yields bytecode for an
// undocumented VM rather than the original logic.
//
// This package is the *client* half: the interpreter plus the ISA
// contract. The compiler frontend (source language → bytecode) lives in
// the private kamienclave-server repo and never ships here. The reference
// assembler in asm.go exists only so the VM can be exercised in tests
// without that frontend.
//
// Scope of v1: scalar values (null, bool, number, string) plus
// reference-semantics arrays and string-keyed objects, arithmetic,
// comparisons, locals, structured control flow, indexing, and host
// calls. Closures are intentionally out of scope for now.
package bytecode

import (
	"sort"
	"strconv"
)

// Kind tags the dynamic type of a Value.
type Kind uint8

const (
	KindNull Kind = iota
	KindBool
	KindNumber
	KindString
	KindArray
	KindObject
)

// Value is the VM's tagged union. Scalars are passed by copy; an array
// carries a pointer to its backing slice, giving JS-like reference
// semantics (index assignment through one Value is visible through
// another that aliases the same array).
type Value struct {
	Kind Kind
	num  float64
	str  string
	b    bool
	arr  *[]Value
	obj  *map[string]Value
}

// Null returns the singleton null value.
func Null() Value { return Value{Kind: KindNull} }

// Bool wraps a boolean.
func Bool(b bool) Value { return Value{Kind: KindBool, b: b} }

// Number wraps a float64.
func Number(f float64) Value { return Value{Kind: KindNumber, num: f} }

// String wraps a string.
func String(s string) Value { return Value{Kind: KindString, str: s} }

// Array wraps a slice as a reference-semantics array value. The backing
// slice is shared; callers must not assume copies are independent.
func Array(elems []Value) Value { return Value{Kind: KindArray, arr: &elems} }

// Elems returns the backing slice of an array value (nil for non-arrays).
func (v Value) Elems() []Value {
	if v.arr == nil {
		return nil
	}
	return *v.arr
}

// Object wraps a string-keyed map as a reference-semantics object value.
func Object(m map[string]Value) Value { return Value{Kind: KindObject, obj: &m} }

// Props returns the backing map of an object value (nil for non-objects).
func (v Value) Props() map[string]Value {
	if v.obj == nil {
		return nil
	}
	return *v.obj
}

// Num returns the numeric payload (0 for non-numbers).
func (v Value) Num() float64 { return v.num }

// Str returns the string payload ("" for non-strings).
func (v Value) Str() string { return v.str }

// B returns the boolean payload (false for non-bools).
func (v Value) B() bool { return v.b }

// Truthy applies JS-like truthiness: null is false, 0 / NaN are false,
// empty string is false, everything else true.
func (v Value) Truthy() bool {
	switch v.Kind {
	case KindNull:
		return false
	case KindBool:
		return v.b
	case KindNumber:
		return v.num != 0 && v.num == v.num // NaN != NaN
	case KindString:
		return v.str != ""
	case KindArray, KindObject:
		return true // like a JS object reference
	default:
		return false
	}
}

// Equal reports strict, same-kind equality. No cross-kind coercion: this
// keeps the VM's semantics predictable and easy to mirror server-side.
func (v Value) Equal(o Value) bool {
	if v.Kind != o.Kind {
		return false
	}
	switch v.Kind {
	case KindNull:
		return true
	case KindBool:
		return v.b == o.b
	case KindNumber:
		return v.num == o.num
	case KindString:
		return v.str == o.str
	case KindArray:
		return v.arr == o.arr // reference identity
	case KindObject:
		return v.obj == o.obj // reference identity
	default:
		return false
	}
}

// Display renders a value for log()-style output.
func (v Value) Display() string {
	switch v.Kind {
	case KindNull:
		return "null"
	case KindBool:
		if v.b {
			return "true"
		}
		return "false"
	case KindNumber:
		return strconv.FormatFloat(v.num, 'g', -1, 64)
	case KindString:
		return v.str
	case KindArray:
		out := "["
		for i, e := range v.Elems() {
			if i > 0 {
				out += ","
			}
			out += e.Display()
		}
		return out + "]"
	case KindObject:
		m := v.Props()
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys) // deterministic rendering
		out := "{"
		for i, k := range keys {
			if i > 0 {
				out += ","
			}
			out += k + ":" + m[k].Display()
		}
		return out + "}"
	default:
		return "<?>"
	}
}
