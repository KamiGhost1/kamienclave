package host

import (
	"time"

	"github.com/KamiGhost1/kamienclave/runtime/bytecode"
)

// Host-call ids form the ABI contract between the server-side compiler
// and the client interpreter (TECHNICAL.md §7.2.1); the canonical
// definitions live in the bytecode package (bytecode.HostLog, ...). The
// mechanism (a generic HOSTCALL opcode dispatching on id) is extensible;
// the registered set below is the deny-by-default whitelist.

// HostTable builds the bytecode VM's host dispatch table from this
// bridge's whitelisted surface. It is the single audit point for what a
// bytecode payload can reach — mirroring Install for the goja path.
func (b *Bridge) HostTable() bytecode.HostTable {
	if b.Log == nil {
		b.Log = DiscardLogger{}
	}
	if b.Env == nil {
		b.Env = map[string]string{}
	}
	if b.MaxSleep == 0 {
		b.MaxSleep = 5 * time.Second
	}

	return bytecode.HostTable{
		bytecode.HostLog: func(args []bytecode.Value) (bytecode.Value, error) {
			parts := make([]any, len(args))
			format := ""
			for i, a := range args {
				if i > 0 {
					format += " "
				}
				format += "%s"
				parts[i] = a.Display()
			}
			b.Log.Logf(format, parts...)
			return bytecode.Null(), nil
		},
		bytecode.HostEnvGet: func(args []bytecode.Value) (bytecode.Value, error) {
			if len(args) == 0 {
				return bytecode.String(""), nil
			}
			return bytecode.String(b.Env[args[0].Str()]), nil
		},
		bytecode.HostSleep: func(args []bytecode.Value) (bytecode.Value, error) {
			if len(args) == 0 {
				return bytecode.Null(), nil
			}
			ms := args[0].Num()
			if ms <= 0 {
				return bytecode.Null(), nil
			}
			d := time.Duration(ms) * time.Millisecond
			if d > b.MaxSleep {
				d = b.MaxSleep
			}
			time.Sleep(d)
			return bytecode.Null(), nil
		},
	}
}
