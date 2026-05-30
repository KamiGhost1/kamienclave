package cliargs

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/KamiGhost1/kamienclave/crypto/zeroize"
	"github.com/KamiGhost1/kamienclave/internal/buildinfo"
	"github.com/KamiGhost1/kamienclave/internal/hardening"
	"github.com/KamiGhost1/kamienclave/runtime/host"
	"github.com/KamiGhost1/kamienclave/runtime/vm"
)

// run subcommand lives in run.go.

func NewRootCommand(info buildinfo.Info) *cobra.Command {
	root := &cobra.Command{
		Use:           "enclave",
		Short:         "enclave — licensed in-memory payload runner",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(newVersionCmd(info))
	root.AddCommand(newRunCmd())
	root.AddCommand(newLocalCmd())
	addDemoCmd(root) // no-op unless built with `-tags demo`
	return root
}

func newVersionCmd(info buildinfo.Info) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print build information",
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(),
				"enclave %s (%s) variant=%s policy=%s built=%s\n",
				info.Version, info.Commit, info.Variant, hardening.Mode, info.Date,
			)
			return err
		},
	}
}

// newLocalCmd runs a JS file straight from disk through the same VM
// the production "run" subcommand will eventually feed from the
// server. Dev-only: lets us exercise the whole in-memory runtime path
// without standing up the licence backend.
func newLocalCmd() *cobra.Command {
	var (
		file    string
		timeout time.Duration
		quiet   bool
	)
	c := &cobra.Command{
		Use:   "local",
		Short: "Run a local JavaScript file in the in-memory runtime (dev mode)",
		Long: `local loads a JavaScript file from disk and executes it in the
in-memory runtime exactly as the production fetch flow will. The host
bridge is installed in its default permissive form (log/env/sleep).

Intended for development, integration tests and manual smoke checks.
The production "run" subcommand bypasses this and only ever consumes
payloads received from the licence server.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if file == "" {
				return fmt.Errorf("--file is required")
			}
			src, err := os.ReadFile(file)
			if err != nil {
				return fmt.Errorf("read payload: %w", err)
			}
			defer zeroize.Bytes(src)

			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()

			// Honour Ctrl-C so a runaway script can be interrupted.
			ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
			defer stop()

			v := vm.New(vm.Options{UseJSONTagMapper: true})
			defer v.Close()

			b := host.New()
			if quiet {
				b.Log = host.DiscardLogger{}
			} else {
				b.Log = host.WriterLogger{W: cmd.OutOrStdout()}
			}
			// Pass through whitelisted env vars. Keep this list tiny.
			for _, k := range []string{"ENCLAVE_LOCAL_USER", "LANG", "TZ"} {
				if v := os.Getenv(k); v != "" {
					b.Env[k] = v
				}
			}

			if err := b.Install(v); err != nil {
				return fmt.Errorf("install host bridge: %w", err)
			}

			// Run consumes src — zeroize on the deferred path is a
			// belt-and-suspenders backup.
			val, err := v.Run(ctx, file, src)
			if err != nil {
				return err
			}
			if !quiet && val != nil {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "result: %s\n", val.String())
			}
			return nil
		},
	}
	c.Flags().StringVarP(&file, "file", "f", "", "Path to JavaScript file to execute")
	c.Flags().DurationVarP(&timeout, "timeout", "t", 30*time.Second, "Maximum execution time")
	c.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress log and result output")
	return c
}
