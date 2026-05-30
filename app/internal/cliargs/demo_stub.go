//go:build !demo

package cliargs

import "github.com/spf13/cobra"

// addDemoCmd is the default no-op variant. The `demo` subcommand only
// exists in builds tagged with `demo` — see demo.go.
func addDemoCmd(_ *cobra.Command) {}
