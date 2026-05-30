//go:build linux

package apprunner

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/KamiGhost1/kamienclave/encpkg"
)

// TestNodeLauncherInMemoryRun drives the real launch chain (memfd ->
// stdin -> `node -`) against a real Node runtime when available: the
// in-memory bundle is a Node script that reports its core rlimit (read
// from /proc/self/limits) and an env var. This verifies the bundle is
// delivered in-memory (no disk path), env passthrough works, and child
// hardening set RLIMIT_CORE=0.
func TestNodeLauncherInMemoryRun(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}

	script := `
const fs = require('fs');
const lim = fs.readFileSync('/proc/self/limits','utf8')
  .split('\n').find(l => l.startsWith('Max core file size')) || '';
console.log('CORE:' + lim.replace(/\s+/g,' ').trim());
console.log('MARKER:' + (process.env.MARKER || ''));
`
	var out bytes.Buffer
	l := &NodeLauncher{NodePath: node, Stdout: &out, Stderr: &out}
	app := App{
		Manifest: &encpkg.Manifest{Entrypoint: "index.js"},
		Bundle:   []byte(script),
		Env:      map[string]string{"MARKER": "ok-123"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := l.Launch(ctx, app); err != nil {
		t.Fatalf("Launch: %v\noutput:\n%s", err, out.String())
	}

	got := out.String()
	if !strings.Contains(got, "MARKER:ok-123") {
		t.Errorf("env passthrough failed; output:\n%s", got)
	}
	// "Max core file size 0 0 bytes" => soft limit 0.
	if !strings.Contains(got, "Max core file size 0 ") {
		t.Errorf("child core limit not 0; output:\n%s", got)
	}
}
