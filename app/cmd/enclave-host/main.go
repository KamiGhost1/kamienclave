// Command enclave-host is the full-application client loader (режим B,
// docs/DRAFT-fullapp-delivery.md §5): it unlocks a license bundle,
// fetches the encrypted .encpkg from the server, verifies+decrypts it,
// and runs the contained Node application entirely from memory (Linux
// memfd, no persistent disk).
//
// It is the режим-B counterpart of `enclave run` (which executes bytecode
// in the mini-VM). Both share transport, licensing and hardening.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/KamiGhost1/kamienclave/apprunner"
	"github.com/KamiGhost1/kamienclave/crypto/zeroize"
	"github.com/KamiGhost1/kamienclave/internal/hardening"
	"github.com/KamiGhost1/kamienclave/internal/hardening/panicguard"
	"github.com/KamiGhost1/kamienclave/internal/hardening/secrets"
	"github.com/KamiGhost1/kamienclave/license"
	"github.com/KamiGhost1/kamienclave/transport"
	"github.com/KamiGhost1/kamienclave/transport/pin"
)

func main() {
	defer panicguard.Recover()
	stop := hardening.Init()
	defer stop()

	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	var (
		blobFile, caFile, tmpDir    string
		insecureNoPin, insecureCert bool
		timeout                     time.Duration
	)
	root := &cobra.Command{
		Use:           "enclave-host",
		Short:         "kamienclave full-application loader (режим B)",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	run := &cobra.Command{
		Use:   "run",
		Short: "Fetch and run the licensed application in memory",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFlow(cmd, blobFile, caFile, tmpDir, insecureNoPin, insecureCert, timeout)
		},
	}
	run.Flags().StringVar(&blobFile, "license-file", "", "Path to the sealed license bundle")
	run.Flags().StringVar(&caFile, "ca", "", "Extra CA bundle (PEM) for the server")
	run.Flags().StringVar(&tmpDir, "tmpdir", "", "RAM-backed dir for the transient bundle (default /dev/shm; raise size for large bundles)")
	run.Flags().BoolVar(&insecureNoPin, "insecure-no-pin", false, "Skip SPKI pin check (dev only)")
	run.Flags().BoolVar(&insecureCert, "insecure-no-cert", false, "Skip TLS chain verification (dev only)")
	run.Flags().DurationVarP(&timeout, "timeout", "t", 0, "Fetch timeout (0 = no timeout on the app run)")
	_ = run.MarkFlagRequired("license-file")
	root.AddCommand(run)
	return root
}

func runFlow(cmd *cobra.Command, blobFile, caFile, tmpDir string, noPin, noCert bool, timeout time.Duration) error {
	// Signals interrupt the (potentially long-lived) child application.
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	encrypted, err := os.ReadFile(blobFile)
	if err != nil {
		return fmt.Errorf("read license: %w", err)
	}
	pass, err := license.PromptPassphrase(os.Stdin, cmd.ErrOrStderr(), "license passphrase: ")
	if err != nil {
		return err
	}
	defer zeroize.Bytes(pass)

	bundle, err := license.Unlock(pass, encrypted)
	if err != nil {
		return fmt.Errorf("unlock: %w", err)
	}
	defer bundle.Wipe()
	secrets.Register(bundle.ClientPriv)
	secrets.Register(bundle.AppDecryptKey)

	if bundle.Mode != license.ModeFullApp {
		return fmt.Errorf("license mode is %q; enclave-host serves only %q (use `enclave run` for bytecode)",
			bundle.Mode, license.ModeFullApp)
	}

	cli, err := buildClient(bundle, caFile, noPin, noCert, timeout)
	if err != nil {
		return err
	}

	// Fetch has its own (short) timeout; the app itself runs unbounded.
	fetchCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		fetchCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	pkg, err := transport.Fetch(fetchCtx, cli, transport.FetchParams{
		Product:          "enclave",
		Build:            hardening.Mode,
		ClientVersion:    "0.0.0-dev",
		LicenseID:        bundle.LicenseID,
		ClientSigningKey: bundle.ClientPriv,
		ServerVerifyKey:  bundle.ServerPub,
	})
	if err != nil {
		return fmt.Errorf("fetch: %w", err)
	}
	defer zeroize.Bytes(pkg)

	launcher := &apprunner.NodeLauncher{TmpDir: tmpDir, Stdout: os.Stdout, Stderr: os.Stderr}
	return apprunner.Run(ctx, launcher, pkg, bundle.AppDecryptKey, bundle.ServerPub, osLookupEnv)
}

func osLookupEnv(k string) (string, bool) { return os.LookupEnv(k) }

func buildClient(bundle *license.Bundle, caFile string, noPin, noCert bool, timeout time.Duration) (*transport.Client, error) {
	cfg := transport.Config{ServerURL: bundle.ServerURL, Timeout: timeout}
	if !noPin {
		cfg.Pins = pin.NewSet(bundle.SPKIPin)
	} else {
		cfg.AllowAnyServerCert = true
	}
	if noCert {
		cfg.AllowAnyServerCert = true
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("ca: invalid PEM")
		}
		cfg.RootCAs = &tls.Config{RootCAs: pool}
	}
	return transport.NewClient(cfg)
}
