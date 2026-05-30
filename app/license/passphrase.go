package license

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// PromptPassphrase reads a passphrase from the TTY without echoing.
// If stdin is not a terminal (e.g. piped input from CI) the value is
// read line-by-line from r instead. The returned slice is owned by
// the caller — wipe it via zeroize.Bytes when done.
//
// If ENCLAVE_PASSPHRASE is set the prompt is skipped entirely and its
// value is returned. Intended for non-interactive automation.
func PromptPassphrase(r io.Reader, w io.Writer, prompt string) ([]byte, error) {
	if env := strings.TrimSpace(os.Getenv("ENCLAVE_PASSPHRASE")); env != "" {
		// Copy so the caller can wipe without smashing the env string.
		return append([]byte(nil), env...), nil
	}

	if f, ok := r.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		if _, err := fmt.Fprint(w, prompt); err != nil {
			return nil, err
		}
		b, err := term.ReadPassword(int(f.Fd()))
		_, _ = fmt.Fprintln(w)
		if err != nil {
			return nil, fmt.Errorf("passphrase: %w", err)
		}
		if len(b) == 0 {
			return nil, errors.New("passphrase: empty input")
		}
		return b, nil
	}

	// Fallback path for non-TTY stdin.
	br := bufio.NewReader(r)
	line, err := br.ReadString('\n')
	if err != nil && (line == "" || err != io.EOF) {
		return nil, fmt.Errorf("passphrase: read: %w", err)
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return nil, errors.New("passphrase: empty input")
	}
	return []byte(line), nil
}
