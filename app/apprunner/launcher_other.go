//go:build !linux

package apprunner

import (
	"context"
	"errors"
	"io"
)

// NodeLauncher is unavailable off Linux: the no-disk memfd path is
// Linux-specific. A tmpfs/tempfile fallback could be added per-OS, but it
// weakens the in-memory guarantee, so it is intentionally absent here
// (docs/DRAFT-fullapp-delivery.md §9 Q6).
type NodeLauncher struct {
	NodePath string
	Stdout   io.Writer
	Stderr   io.Writer
}

var errUnsupported = errors.New("apprunner: in-memory NodeLauncher is only implemented on Linux")

// Launch always fails off Linux.
func (n *NodeLauncher) Launch(_ context.Context, _ App) error { return errUnsupported }
