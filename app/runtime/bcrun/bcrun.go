// Package bcrun is the client-side glue that turns raw payload bytes
// from the licence server into a bytecode execution: derive the build's
// opcode table, decode (decrypting the constant pool when a key is set),
// and run on the mini-VM behind the whitelisted host bridge.
//
// It is the bytecode counterpart of the goja path in internal/runtime/vm
// and is selected by the backend build (TECHNICAL.md §4.3, §7.1).
package bcrun

import (
	"context"

	"github.com/KamiGhost1/kamienclave/runtime/bytecode"
	"github.com/KamiGhost1/kamienclave/runtime/host"
)

// Run decodes raw under the per-build opcode table derived from
// opcodeSeed and executes it. If constKey is non-empty the constant pool
// is decrypted with it (EncodeEncrypted payloads); otherwise a clear
// pool is assumed. Both opcodeSeed and constKey are per-build secrets the
// client carries (delivered in the licence bundle), never in the payload.
func Run(ctx context.Context, raw []byte, opcodeSeed int64, constKey []byte, b *host.Bridge, lim bytecode.Limits) (bytecode.Value, error) {
	table := bytecode.NewTableFromSeed(opcodeSeed)

	var (
		prog *bytecode.Program
		err  error
	)
	if len(constKey) > 0 {
		prog, err = bytecode.DecodeEncrypted(raw, table, constKey)
	} else {
		prog, err = bytecode.Decode(raw, table)
	}
	if err != nil {
		return bytecode.Value{}, err
	}

	if b == nil {
		b = host.New()
	}
	return prog.Run(ctx, b.HostTable(), lim)
}
