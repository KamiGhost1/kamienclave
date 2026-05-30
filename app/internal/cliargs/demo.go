//go:build demo

package cliargs

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/KamiGhost1/kamienclave/crypto/sign"
	"github.com/KamiGhost1/kamienclave/crypto/zeroize"
	"github.com/KamiGhost1/kamienclave/runtime/host"
	"github.com/KamiGhost1/kamienclave/runtime/vm"
	"github.com/KamiGhost1/kamienclave/transport"
	"github.com/KamiGhost1/kamienclave/transport/mockserver"
	"github.com/KamiGhost1/kamienclave/transport/pin"
)

//go:embed testdata/demo_payload.js
var demoPayload []byte

// addDemoCmd is the build-tag-on variant: registers the `demo`
// subcommand that spins up an in-process mock licence server and
// drives the full fetch→decrypt→vm.Run flow against it.
//
// Build with `go build -tags demo ./cmd/enclave` (or `make build-demo`).
// The default build leaves this subcommand out — see demo_stub.go.
func addDemoCmd(root *cobra.Command) {
	var timeout time.Duration
	c := &cobra.Command{
		Use:   "demo",
		Short: "Run an end-to-end fetch+execute demo against an in-process mock server",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()
			ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
			defer stop()

			srv, err := mockserver.New(demoPayload)
			if err != nil {
				return fmt.Errorf("mockserver: %w", err)
			}
			defer srv.Close()

			clientKey, err := sign.GenerateKey()
			if err != nil {
				return fmt.Errorf("client key: %w", err)
			}
			srv.RegisterClient(clientKey.Public().(ed25519.PublicKey))

			leaf := srv.HTTP.Certificate()
			pool := x509.NewCertPool()
			pool.AddCert(leaf)

			cli, err := transport.NewClient(transport.Config{
				ServerURL: srv.HTTP.URL,
				Pins:      pin.NewSet(pin.Compute(leaf)),
				RootCAs:   &tls.Config{RootCAs: pool},
				Timeout:   timeout,
			})
			if err != nil {
				return fmt.Errorf("client: %w", err)
			}

			plain, err := transport.Fetch(ctx, cli, transport.FetchParams{
				Product:          "enclave",
				Build:            "demo",
				ClientVersion:    "0.0.0-demo",
				LicenseID:        "LCS-DEMO",
				ClientSigningKey: clientKey,
				ServerVerifyKey:  srv.ServerSigningKey.Public().(ed25519.PublicKey),
			})
			if err != nil {
				return fmt.Errorf("fetch: %w", err)
			}
			defer zeroize.Bytes(plain)

			v := vm.New(vm.Options{UseJSONTagMapper: true})
			defer v.Close()

			b := host.New()
			b.Log = host.WriterLogger{W: cmd.OutOrStdout()}
			if err := b.Install(v); err != nil {
				return fmt.Errorf("install host: %w", err)
			}

			val, err := v.Run(ctx, "demo.js", plain)
			if err != nil {
				return fmt.Errorf("run: %w", err)
			}
			if val != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "result: %s\n", val.String())
			}
			return nil
		},
	}
	c.Flags().DurationVarP(&timeout, "timeout", "t", 30*time.Second, "Maximum total time")
	root.AddCommand(c)
}
