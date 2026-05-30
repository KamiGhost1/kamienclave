package license

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestPromptPassphraseFromEnv(t *testing.T) {
	t.Setenv("ENCLAVE_PASSPHRASE", "from-env")
	got, err := PromptPassphrase(strings.NewReader(""), &bytes.Buffer{}, "x: ")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if string(got) != "from-env" {
		t.Fatalf("got %q", got)
	}
}

func TestPromptPassphraseFromStdin(t *testing.T) {
	_ = os.Unsetenv("ENCLAVE_PASSPHRASE")
	in := strings.NewReader("piped-pass\n")
	got, err := PromptPassphrase(in, &bytes.Buffer{}, "x: ")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if string(got) != "piped-pass" {
		t.Fatalf("got %q", got)
	}
}

func TestPromptPassphraseRejectsEmpty(t *testing.T) {
	_ = os.Unsetenv("ENCLAVE_PASSPHRASE")
	if _, err := PromptPassphrase(strings.NewReader("\n"), &bytes.Buffer{}, "x: "); err == nil {
		t.Fatal("empty passphrase must error")
	}
}
