//go:build backend

package cliargs

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/KamiGhost1/kamienclave/license"
	"github.com/KamiGhost1/kamienclave/runtime/bcrun"
	"github.com/KamiGhost1/kamienclave/runtime/bytecode"
	"github.com/KamiGhost1/kamienclave/runtime/host"
)

// executePayload (backend build) decodes the fetched payload as bytecode
// under the build's opcode table and constant key (carried in the
// licence bundle) and runs it on the mini-VM. No readable JS ever exists
// in memory (TECHNICAL.md §7.1).
func executePayload(cmd *cobra.Command, ctx context.Context, plain []byte, bundle *license.Bundle) (string, error) {
	b := host.New()
	b.Log = host.WriterLogger{W: cmd.OutOrStdout()}

	val, err := bcrun.Run(ctx, plain, bundle.BCTableSeed, bundle.BCConstKey, b, bytecode.Limits{})
	if err != nil {
		return "", err
	}
	if val.Kind != bytecode.KindNull {
		return val.Display(), nil
	}
	return "", nil
}
