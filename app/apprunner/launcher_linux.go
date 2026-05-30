//go:build linux

package apprunner

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// NodeLauncher runs the decrypted bundle on Node.js from a RAM-backed
// tmpfs file (default /dev/shm), never touching a persistent disk.
//
// Why tmpfs and not a memfd/stdin (a real B0 lesson — see
// docs/DRAFT-fullapp-delivery §5): real ncc/webpack bundles refuse to run
// from a non-file entry. `node /dev/fd/N` fails because Node's loader
// realpath()s the entry and a memfd resolves to "/memfd:... (deleted)";
// `node -` (stdin) silently fails to bootstrap a webpack bundle (it relies
// on require.main / __filename). A real ncc backend boots fine from a
// real path, so we use a tmpfs path: RAM-only, 0600, unlinked shortly
// after Node opens it (Node keeps running from its open fd, the path
// disappears from the directory), and removed for certain on exit.
//
// Honest scope (§2): this is weaker than a true memfd — the bundle is
// briefly visible as a 0600 file in RAM-backed tmpfs. Mode B already
// cedes root, and root can read the running process's memory regardless,
// so a brief same-user-or-root-readable RAM file is consistent.
type NodeLauncher struct {
	NodePath string    // node binary; defaults to "node" on PATH
	TmpDir   string    // RAM-backed dir for the transient bundle; default /dev/shm
	Stdout   io.Writer // defaults to os.Stdout
	Stderr   io.Writer // defaults to os.Stderr
}

// Launch implements Launcher via `node <tmpfs-path>`.
func (n *NodeLauncher) Launch(ctx context.Context, app App) error {
	nodePath := n.NodePath
	if nodePath == "" {
		p, err := exec.LookPath("node")
		if err != nil {
			return fmt.Errorf("apprunner: node not found: %w", err)
		}
		nodePath = p
	}

	dir := n.TmpDir
	if dir == "" {
		dir = ramTmpDir()
	}
	f, err := os.CreateTemp(dir, "enclave-*.js")
	if err != nil {
		return fmt.Errorf("apprunner: create tmpfs file: %w", err)
	}
	path := f.Name()
	var once sync.Once
	rm := func() { once.Do(func() { _ = os.Remove(path) }) }
	defer rm()

	_ = f.Chmod(0o600)
	if _, err := f.Write(app.Bundle); err != nil {
		_ = f.Close()
		return fmt.Errorf("apprunner: write bundle: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("apprunner: close bundle: %w", err)
	}

	// Harden the child before launch:
	//   - RLIMIT_CORE=0 is process-wide and inherited by the child, so a
	//     crash never writes a core file containing the app's code;
	//   - Pdeathsig=SIGKILL ensures the (long-lived) Node process dies with
	//     the loader rather than lingering with the code resident in memory.
	//
	// Note (§2/§9 Q7): PR_SET_DUMPABLE resets on execve and root bypasses
	// it anyway, so we do not chase it via a re-exec shim.
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})

	args := append([]string{path}, app.Manifest.Args...)
	cmd := exec.CommandContext(ctx, nodePath, args...)
	cmd.Stdout = orStd(n.Stdout, os.Stdout)
	cmd.Stderr = orStd(n.Stderr, os.Stderr)
	cmd.Env = buildEnv(app.Env)
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("apprunner: start node: %w", err)
	}
	// Once Node has opened the entry (it does so at startup), unlink the
	// path: Node keeps running from its open fd and the file vanishes from
	// the directory, shrinking the exposure window to startup only.
	go func() {
		t := time.NewTimer(1500 * time.Millisecond)
		defer t.Stop()
		select {
		case <-t.C:
			rm()
		case <-ctx.Done():
		}
	}()

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("apprunner: node exited: %w", err)
	}
	return nil
}

// ramTmpDir prefers /dev/shm (tmpfs) when usable, falling back to the
// system temp dir (which may be disk-backed — best effort).
func ramTmpDir() string {
	const shm = "/dev/shm"
	if fi, err := os.Stat(shm); err == nil && fi.IsDir() {
		// Probe writability.
		if f, err := os.CreateTemp(shm, ".probe-*"); err == nil {
			name := f.Name()
			_ = f.Close()
			_ = os.Remove(name)
			return shm
		}
	}
	return os.TempDir()
}

func orStd(w io.Writer, def io.Writer) io.Writer {
	if w != nil {
		return w
	}
	return def
}

// buildEnv merges the resolved passthrough env onto the current
// environment so the child Node process sees both.
func buildEnv(extra map[string]string) []string {
	env := os.Environ()
	for k, v := range extra {
		env = append(env, k+"="+v)
	}
	return env
}
