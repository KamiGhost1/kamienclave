package bytecode

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// Program is the decoded, in-memory form the VM executes. Code holds
// logical opcodes (post-permutation), so the interpreter never has to
// consult the OpcodeTable.
type Program struct {
	NumLocals int
	Consts    []Value
	Code      []byte
}

const (
	magic0, magic1, magic2, magic3 = 'D', 'L', 'B', 'C'
	formatVersion                  = 1

	// flagConstsEncrypted marks a payload whose constant pool is
	// ChaCha20-encrypted under a per-build key (see crypt.go). When set,
	// the header carries a random nonce and an explicit region length;
	// DecodeEncrypted runs the keystream before parsing constants.
	flagConstsEncrypted = 1 << 0
)

const (
	tagNull byte = iota
	tagBool
	tagNumber
	tagString
)

var (
	ErrFormat    = errors.New("bytecode: malformed program")
	ErrBadOpcode = errors.New("bytecode: unknown opcode")
	ErrTruncated = errors.New("bytecode: truncated instruction stream")
)

// Encode serialises p to the wire format with a clear constant pool,
// mapping each opcode byte through t. Operands are copied verbatim (they
// are not opcodes and so are not permuted).
func Encode(p *Program, t *OpcodeTable) ([]byte, error) {
	return encode(p, t, nil)
}

// EncodeEncrypted is like Encode but stream-encrypts the constant pool
// under key (a per-build secret, never carried in the payload). A fresh
// random nonce is stored in the header; key + nonce must be reproduced
// by DecodeEncrypted (TECHNICAL.md §8.4). This hides string literals and
// numeric constants from a static dump even when the opcode table leaks.
func EncodeEncrypted(p *Program, t *OpcodeTable, key []byte) ([]byte, error) {
	if len(key) != ConstKeySize {
		return nil, ErrKeySize
	}
	return encode(p, t, key)
}

func encode(p *Program, t *OpcodeTable, key []byte) ([]byte, error) {
	if p == nil {
		return nil, ErrFormat
	}
	if p.NumLocals < 0 || p.NumLocals > 255 {
		return nil, fmt.Errorf("%w: locals out of range", ErrFormat)
	}
	if len(p.Consts) > math.MaxUint16 {
		return nil, fmt.Errorf("%w: too many constants", ErrFormat)
	}

	region, err := appendConsts(nil, p.Consts)
	if err != nil {
		return nil, err
	}

	flags := byte(0)
	var nonce []byte
	if key != nil {
		flags |= flagConstsEncrypted
		nonce = make([]byte, ConstNonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
		if err := xorConsts(region, key, nonce); err != nil {
			return nil, err
		}
	}

	var b []byte
	b = append(b, magic0, magic1, magic2, magic3, formatVersion, flags, byte(p.NumLocals))
	b = binary.BigEndian.AppendUint16(b, uint16(len(p.Consts)))
	if key != nil {
		b = append(b, nonce...)
		b = binary.BigEndian.AppendUint32(b, uint32(len(region)))
	}
	b = append(b, region...)

	wire, err := permuteCode(p.Code, t, true)
	if err != nil {
		return nil, err
	}
	b = binary.BigEndian.AppendUint32(b, uint32(len(wire)))
	b = append(b, wire...)
	return b, nil
}

// appendConsts serialises the constant pool to b and returns the grown
// slice. The encoding is self-delimiting (tag + payload per value).
func appendConsts(b []byte, consts []Value) ([]byte, error) {
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
			if len(c.str) > math.MaxUint16 {
				return nil, fmt.Errorf("%w: constant string too long", ErrFormat)
			}
			b = append(b, tagString)
			b = binary.BigEndian.AppendUint16(b, uint16(len(c.str)))
			b = append(b, c.str...)
		default:
			return nil, fmt.Errorf("%w: bad constant kind", ErrFormat)
		}
	}
	return b, nil
}

// readConsts parses exactly count constants from r.
func readConsts(r *reader, count int) ([]Value, error) {
	consts := make([]Value, 0, count)
	for i := 0; i < count; i++ {
		tag, ok := r.u8()
		if !ok {
			return nil, ErrTruncated
		}
		switch tag {
		case tagNull:
			consts = append(consts, Null())
		case tagBool:
			v, ok := r.u8()
			if !ok {
				return nil, ErrTruncated
			}
			consts = append(consts, Bool(v != 0))
		case tagNumber:
			bits, ok := r.u64()
			if !ok {
				return nil, ErrTruncated
			}
			consts = append(consts, Number(math.Float64frombits(bits)))
		case tagString:
			n, ok := r.u16()
			if !ok {
				return nil, ErrTruncated
			}
			s, ok := r.bytes(int(n))
			if !ok {
				return nil, ErrTruncated
			}
			consts = append(consts, String(string(s)))
		default:
			return nil, fmt.Errorf("%w: bad constant tag", ErrFormat)
		}
	}
	return consts, nil
}

// Decode parses raw into a Program, inverse-mapping opcode bytes through
// t and validating the instruction stream. It only accepts programs with
// a clear constant pool; an encrypted one requires DecodeEncrypted.
func Decode(raw []byte, t *OpcodeTable) (*Program, error) {
	return decode(raw, t, nil)
}

// DecodeEncrypted decodes a program whose constant pool is encrypted
// under key. It also accepts clear-pool programs (key is then ignored),
// so a caller holding the build key can decode either form.
func DecodeEncrypted(raw []byte, t *OpcodeTable, key []byte) (*Program, error) {
	if len(key) != ConstKeySize {
		return nil, ErrKeySize
	}
	return decode(raw, t, key)
}

func decode(raw []byte, t *OpcodeTable, key []byte) (*Program, error) {
	r := &reader{buf: raw}
	if !r.match(magic0, magic1, magic2, magic3) {
		return nil, fmt.Errorf("%w: bad magic", ErrFormat)
	}
	ver, ok := r.u8()
	if !ok || ver != formatVersion {
		return nil, fmt.Errorf("%w: unsupported version", ErrFormat)
	}
	flags, ok := r.u8()
	if !ok {
		return nil, ErrFormat
	}
	nlocals, ok := r.u8()
	if !ok {
		return nil, ErrFormat
	}
	cc, ok := r.u16()
	if !ok {
		return nil, ErrFormat
	}

	if flags&flagConstsEncrypted != 0 {
		if key == nil {
			return nil, ErrKeyRequired
		}
		nonce, ok := r.bytes(ConstNonceSize)
		if !ok {
			return nil, ErrTruncated
		}
		regionLen, ok := r.u32()
		if !ok {
			return nil, ErrFormat
		}
		region, ok := r.bytes(int(regionLen))
		if !ok {
			return nil, ErrTruncated
		}
		plain := make([]byte, len(region))
		copy(plain, region)
		if err := xorConsts(plain, key, nonce); err != nil {
			return nil, err
		}
		cr := &reader{buf: plain}
		consts, err := readConsts(cr, int(cc))
		if err != nil {
			return nil, err
		}
		if cr.pos != len(plain) {
			return nil, fmt.Errorf("%w: trailing bytes in constant region", ErrFormat)
		}
		return finishDecode(r, t, int(nlocals), consts)
	}

	consts, err := readConsts(r, int(cc))
	if err != nil {
		return nil, err
	}
	return finishDecode(r, t, int(nlocals), consts)
}

func finishDecode(r *reader, t *OpcodeTable, nlocals int, consts []Value) (*Program, error) {
	codeLen, ok := r.u32()
	if !ok {
		return nil, ErrFormat
	}
	wire, ok := r.bytes(int(codeLen))
	if !ok {
		return nil, ErrTruncated
	}
	code, err := permuteCode(wire, t, false)
	if err != nil {
		return nil, err
	}
	p := &Program{NumLocals: nlocals, Consts: consts, Code: code}
	if err := p.validate(); err != nil {
		return nil, err
	}
	return p, nil
}

// permuteCode walks the instruction stream and translates opcode bytes.
// encode=true maps logical->wire, encode=false maps wire->logical. Either
// way operands are copied verbatim, which requires knowing operand widths
// — hence the walk also validates that no instruction is truncated.
func permuteCode(in []byte, t *OpcodeTable, encode bool) ([]byte, error) {
	out := make([]byte, 0, len(in))
	for i := 0; i < len(in); {
		var op Op
		if encode {
			op = Op(in[i])
			if !op.valid() {
				return nil, ErrBadOpcode
			}
			out = append(out, t.wire(op))
		} else {
			op = t.logical(in[i])
			if !op.valid() {
				return nil, ErrBadOpcode
			}
			out = append(out, byte(op))
		}
		i++
		w := operandWidth(op)
		if i+w > len(in) {
			return nil, ErrTruncated
		}
		out = append(out, in[i:i+w]...)
		i += w
	}
	return out, nil
}

// validate confirms every opcode is known, operands fit, constant and
// local indices are in range, and jump targets land on the start of an
// instruction. Doing this once up front lets the interpreter hot loop
// skip per-instruction bounds checks on operands.
func (p *Program) validate() error {
	starts := map[int]bool{}
	// First pass: record instruction boundaries and check operand ranges.
	for i := 0; i < len(p.Code); {
		starts[i] = true
		op := Op(p.Code[i])
		if !op.valid() {
			return ErrBadOpcode
		}
		w := operandWidth(op)
		if i+1+w > len(p.Code) {
			return ErrTruncated
		}
		switch op {
		case OpPushConst:
			idx := int(binary.BigEndian.Uint16(p.Code[i+1 : i+3]))
			if idx >= len(p.Consts) {
				return fmt.Errorf("%w: const index out of range", ErrFormat)
			}
		case OpLoad, OpStore:
			if int(p.Code[i+1]) >= p.NumLocals {
				return fmt.Errorf("%w: local index out of range", ErrFormat)
			}
		}
		i += 1 + w
	}
	starts[len(p.Code)] = true // a jump to the very end halts cleanly
	// Second pass: jump targets must be instruction boundaries.
	for i := 0; i < len(p.Code); {
		op := Op(p.Code[i])
		w := operandWidth(op)
		if op == OpJmp || op == OpJmpIfFalse {
			rel := int(int16(binary.BigEndian.Uint16(p.Code[i+1 : i+3])))
			target := i + 1 + w + rel
			if !starts[target] {
				return fmt.Errorf("%w: jump target not an instruction boundary", ErrFormat)
			}
		}
		i += 1 + w
	}
	return nil
}

// reader is a tiny bounds-checked cursor over a byte slice.
type reader struct {
	buf []byte
	pos int
}

func (r *reader) match(bs ...byte) bool {
	if r.pos+len(bs) > len(r.buf) {
		return false
	}
	for i, b := range bs {
		if r.buf[r.pos+i] != b {
			return false
		}
	}
	r.pos += len(bs)
	return true
}

func (r *reader) u8() (byte, bool) {
	if r.pos+1 > len(r.buf) {
		return 0, false
	}
	b := r.buf[r.pos]
	r.pos++
	return b, true
}

func (r *reader) u16() (uint16, bool) {
	if r.pos+2 > len(r.buf) {
		return 0, false
	}
	v := binary.BigEndian.Uint16(r.buf[r.pos:])
	r.pos += 2
	return v, true
}

func (r *reader) u32() (uint32, bool) {
	if r.pos+4 > len(r.buf) {
		return 0, false
	}
	v := binary.BigEndian.Uint32(r.buf[r.pos:])
	r.pos += 4
	return v, true
}

func (r *reader) u64() (uint64, bool) {
	if r.pos+8 > len(r.buf) {
		return 0, false
	}
	v := binary.BigEndian.Uint64(r.buf[r.pos:])
	r.pos += 8
	return v, true
}

func (r *reader) bytes(n int) ([]byte, bool) {
	if n < 0 || r.pos+n > len(r.buf) {
		return nil, false
	}
	b := r.buf[r.pos : r.pos+n]
	r.pos += n
	return b, true
}
