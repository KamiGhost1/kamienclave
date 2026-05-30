//go:build !backend

package cliargs

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/KamiGhost1/kamienclave/license"
	"github.com/KamiGhost1/kamienclave/runtime/host"
	"github.com/KamiGhost1/kamienclave/runtime/vm"
)

// executePayload (public/default build) runs the fetched payload as
// JavaScript on the goja runtime. The bytecode mini-VM is backend-only
// (see run_exec_backend.go and TECHNICAL.md §4.3).
func executePayload(cmd *cobra.Command, ctx context.Context, plain []byte, _ *license.Bundle) (string, error) {
	v := vm.New(vm.Options{UseJSONTagMapper: true})
	defer v.Close()

	b := host.New()
	b.Log = host.WriterLogger{W: cmd.OutOrStdout()}
	if err := b.Install(v); err != nil {
		return "", fmt.Errorf("install host: %w", err)
	}

	val, err := v.Run(ctx, "payload.js", plain)
	if err != nil {
		return "", err
	}
	if val != nil {
		return val.String(), nil
	}
	return "", nil
}
