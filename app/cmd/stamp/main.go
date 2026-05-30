// Command stamp appends kamienclave's integrity trailer to a built binary.
//
// It is a build-pipeline tool, not part of the shipped client. Run it as
// the last step of a release build — after garble — so the trailer
// reflects the final bytes:
//
//	go build ... -o bin/enclave-vm
//	go run ./cmd/stamp bin/enclave-vm
//
// Stamping is idempotent: re-running replaces an existing trailer.
package main

import (
	"fmt"
	"os"

	"github.com/KamiGhost1/kamienclave/internal/hardening/integrity"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: stamp <binary>")
		os.Exit(2)
	}
	if err := integrity.Stamp(os.Args[1]); err != nil {
		fmt.Fprintf(os.Stderr, "stamp: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("stamped %s\n", os.Args[1])
}
