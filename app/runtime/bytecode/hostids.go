package bytecode

// Standard host-call ids. These are part of the ABI contract that both
// halves of the system share (the server-side compiler emits HOSTCALL
// with these ids; the client interpreter dispatches on them), so they
// live with the ISA rather than in the client-only host package.
//
// Ids are append-only: never renumber an existing primitive, so an older
// loader keeps working against newer payloads that don't use new ids.
const (
	HostLog    uint8 = 1 // log(args...)        -> null
	HostEnvGet uint8 = 2 // env.get(key string) -> string
	HostSleep  uint8 = 3 // sleep(ms number)    -> null
)
