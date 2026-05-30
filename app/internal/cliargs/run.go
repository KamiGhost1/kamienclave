package cliargs

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

	"github.com/KamiGhost1/kamienclave/crypto/zeroize"
	"github.com/KamiGhost1/kamienclave/internal/hardening"
	"github.com/KamiGhost1/kamienclave/internal/hardening/secrets"
	"github.com/KamiGhost1/kamienclave/license"
	"github.com/KamiGhost1/kamienclave/transport"
	"github.com/KamiGhost1/kamienclave/transport/pin"
)

func newRunCmd() *cobra.Command {
	var (
		blobFile       string
		caFile         string
		insecureNoPin  bool
		insecureNoCert bool
		timeout        time.Duration
	)
	c := &cobra.Command{
		Use:   "run",
		Short: "Unlock the licence bundle and execute the freshly-fetched payload",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFlow(cmd, runOpts{
				blobFile:       blobFile,
				caFile:         caFile,
				insecureNoPin:  insecureNoPin,
				insecureNoCert: insecureNoCert,
				timeout:        timeout,
			})
		},
	}
	c.Flags().StringVar(&blobFile, "license-file", "", "Path to encrypted licence blob (overrides embedded blob)")
	c.Flags().StringVar(&caFile, "ca", "", "Extra CA bundle (PEM) for the licence server")
	c.Flags().BoolVar(&insecureNoPin, "insecure-no-pin", false, "Skip SPKI pin check (dev only)")
	c.Flags().BoolVar(&insecureNoCert, "insecure-no-cert", false, "Skip TLS chain verification (dev only)")
	c.Flags().DurationVarP(&timeout, "timeout", "t", 30*time.Second, "Total operation timeout")
	return c
}

type runOpts struct {
	blobFile       string
	caFile         string
	insecureNoPin  bool
	insecureNoCert bool
	timeout        time.Duration
}

func runFlow(cmd *cobra.Command, opts runOpts) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), opts.timeout)
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	encrypted, err := loadBlob(opts.blobFile)
	if err != nil {
		return err
	}

	pass, err := license.PromptPassphrase(os.Stdin, cmd.ErrOrStderr(),
		"licence passphrase: ")
	if err != nil {
		return err
	}
	defer zeroize.Bytes(pass)

	bundle, err := license.Unlock(pass, encrypted)
	if err != nil {
		return fmt.Errorf("unlock: %w", err)
	}
	defer bundle.Wipe()
	// Register the live key material so a fatal signal or panic wipes it
	// even though the happy-path defer above wouldn't run.
	secrets.Register(bundle.ClientPriv)
	secrets.Register(bundle.BCConstKey)

	cli, err := buildClient(bundle, opts)
	if err != nil {
		return err
	}

	plain, err := transport.Fetch(ctx, cli, transport.FetchParams{
		Product:          "enclave",
		Build:            hardening.Mode, // "public" | "backend"
		ClientVersion:    "0.0.0-dev",
		LicenseID:        bundle.LicenseID,
		ClientSigningKey: bundle.ClientPriv,
		ServerVerifyKey:  bundle.ServerPub,
	})
	if err != nil {
		return fmt.Errorf("fetch: %w", err)
	}
	defer zeroize.Bytes(plain)
	secrets.Register(plain)

	// executePayload is build-tag specific: the backend build decodes and
	// runs bytecode (run_exec_backend.go); the default/public build runs
	// JavaScript on goja (run_exec_public.go).
	result, err := executePayload(cmd, ctx, plain, bundle)
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}
	if result != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "result: %s\n", result)
	}
	return nil
}

func loadBlob(path string) ([]byte, error) {
	if path != "" {
		return license.LoadFile(path)
	}
	data, err := license.LoadEmbedded()
	if err != nil {
		if errors.Is(err, license.ErrNoEmbeddedBlob) {
			return nil, errors.New("run: no embedded licence blob; pass --license-file")
		}
		return nil, err
	}
	return data, nil
}

func buildClient(bundle *license.Bundle, opts runOpts) (*transport.Client, error) {
	cfg := transport.Config{
		ServerURL: bundle.ServerURL,
		Timeout:   opts.timeout,
	}
	if !opts.insecureNoPin {
		cfg.Pins = pin.NewSet(bundle.SPKIPin)
	} else {
		cfg.AllowAnyServerCert = true
	}
	if opts.insecureNoCert {
		cfg.AllowAnyServerCert = true
	}
	if opts.caFile != "" {
		pem, err := os.ReadFile(opts.caFile)
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
