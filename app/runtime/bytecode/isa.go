package bytecode

import "math/rand"

// Op is a logical opcode. The in-memory Program holds logical opcodes;
// the wire format maps them through an OpcodeTable so that the byte
// value of each opcode can be randomised per server build.
type Op uint8

const (
	OpNop        Op = iota // -            no-op
	OpPushConst            // u16 constIdx push consts[idx]
	OpPop                  // -            discard top
	OpDup                  // -            duplicate top
	OpLoad                 // u8  slot     push locals[slot]
	OpStore                // u8  slot     locals[slot] = pop()
	OpAdd                  // -            numeric add / string concat
	OpSub                  // -
	OpMul                  // -
	OpDiv                  // -
	OpMod                  // -
	OpNeg                  // -            unary minus
	OpEq                   // -            strict equality -> bool
	OpNe                   // -
	OpLt                   // -
	OpLe                   // -
	OpGt                   // -
	OpGe                   // -
	OpNot                  // -            logical not -> bool
	OpJmp                  // i16 rel      pc += rel
	OpJmpIfFalse           // i16 rel      pc += rel if !pop().Truthy()
	OpHostCall             // u8 id, u8 n  call host[id] with n args
	OpReturn               // -            stop, completion = pop() (or null)
	OpHalt                 // -            stop, completion = null
	OpNewArray             // u16 n        pop n values -> push array
	OpIndexGet             // -            pop idx, arr -> push arr[idx]
	OpIndexSet             // -            pop val, idx, coll; coll[idx]=val; push val
	OpLen                  // -            pop arr/string -> push length
	OpNewObject            // u16 n        pop n key/value pairs -> push object

	numOps // sentinel; must stay last
)

// operandWidth returns the number of operand bytes that follow op in the
// instruction stream. Used by the decoder to walk instructions and by
// the assembler to lay them out.
func operandWidth(op Op) int {
	switch op {
	case OpPushConst, OpJmp, OpJmpIfFalse, OpHostCall, OpNewArray, OpNewObject:
		return 2
	case OpLoad, OpStore:
		return 1
	default:
		return 0
	}
}

func (op Op) valid() bool { return op < numOps }

// OpcodeTable is a bijection between logical opcodes and the byte values
// written to the wire. A randomised table means a disassembler built for
// one leaked build does not transfer to another (TECHNICAL.md §8.4).
//
// The table is a build-time secret shared by the server-side compiler
// and this interpreter; it is never carried inside a payload. In this
// repo it is supplied explicitly to Encode/Decode so the VM can be
// tested under arbitrary permutations.
type OpcodeTable struct {
	enc [256]byte // logical op -> wire byte
	dec [256]Op   // wire byte  -> logical op
}

// IdentityTable maps every opcode to its own numeric value. Useful as a
// readable default and in tests.
func IdentityTable() *OpcodeTable {
	t := &OpcodeTable{}
	for i := 0; i < 256; i++ {
		t.enc[i] = byte(i)
		t.dec[i] = Op(i)
	}
	return t
}

// NewTableFromSeed derives a deterministic permutation of all 256 byte
// values from seed. Determinism lets a build pin its table by seed; the
// permutation covers the whole byte space so unused values are still
// shuffled, denying the analyst a fixed opcode map.
func NewTableFromSeed(seed int64) *OpcodeTable {
	perm := rand.New(rand.NewSource(seed)).Perm(256)
	t := &OpcodeTable{}
	for logical, wire := range perm {
		t.enc[logical] = byte(wire)
		t.dec[wire] = Op(logical)
	}
	return t
}

func (t *OpcodeTable) wire(op Op) byte   { return t.enc[op] }
func (t *OpcodeTable) logical(b byte) Op { return t.dec[b] }
