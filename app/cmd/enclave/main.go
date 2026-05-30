// Package main is the entry point for the kamienclave CLI.
//
// Lifecycle:
//
//  1. hardening.Init() — anti-dump lockdown, integrity check, debugger
//     probes; produces a stop func for the background re-probe;
//  2. cliargs.NewRootCommand — Cobra command tree;
//  3. Execute — dispatch to the subcommand (run / local / demo / ...).
//
// Build metadata is injected via -ldflags; see Makefile.
package main

import (
	"fmt"
	"os"

	"github.com/KamiGhost1/kamienclave/internal/buildinfo"
	"github.com/KamiGhost1/kamienclave/internal/cliargs"
	"github.com/KamiGhost1/kamienclave/internal/hardening"
	"github.com/KamiGhost1/kamienclave/internal/hardening/panicguard"
)

func main() {
	// Outermost defer: an unrecovered panic is wiped + reported, and on
	// the backend build the process vanishes without a stack trace.
	defer panicguard.Recover()

	stopHardening := hardening.Init()
	defer stopHardening()

	cmd := cliargs.NewRootCommand(buildinfo.Info{
		Version: version,
		Commit:  commit,
		Date:    date,
		Variant: variant,
	})
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// Overridden via -ldflags="-X 'main.version=...'" by the build pipeline.
var (
	version = "0.0.0-dev"
	commit  = "none"
	date    = "unknown"
	variant = "public" // "public" | "backend"
)
