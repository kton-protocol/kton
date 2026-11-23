package keys

import (
	"bytes"
	"fmt"
	"os"

	"golang.org/x/term"
)

// EnvPassphrase is the environment variable the reference CLIs read a key's passphrase from, for CI
// and scripts. It is read, never set or logged.
const EnvPassphrase = "KTON_KEY_PASSPHRASE"

// CLIPassphrase is the Passphrase the reference CLIs use: $KTON_KEY_PASSPHRASE if it is set, else a
// prompt on the terminal with no echo. Without either it refuses and says how to supply one; it never
// takes a passphrase from argv or a file.
func CLIPassphrase(keyPath string) ([]byte, error) {
	if p, ok := os.LookupEnv(EnvPassphrase); ok {
		return []byte(p), nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, fmt.Errorf("the key is encrypted and there is no terminal to ask for its "+
			"passphrase: set %s", EnvPassphrase)
	}
	fmt.Fprintf(os.Stderr, "passphrase for %s: ", keyPath)
	p, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	return p, err
}

// NewPassphrase is how keygen --encrypt gets a passphrase: $KTON_KEY_PASSPHRASE if it is set, else
// asked twice on the terminal, and the two must match. An empty passphrase is refused.
func NewPassphrase(keyPath string) ([]byte, error) {
	if p, ok := os.LookupEnv(EnvPassphrase); ok {
		if p == "" {
			return nil, fmt.Errorf("%s is set but empty: an empty passphrase encrypts nothing", EnvPassphrase)
		}
		return []byte(p), nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, fmt.Errorf("no terminal to ask for a passphrase for %s: set %s", keyPath, EnvPassphrase)
	}
	fmt.Fprintf(os.Stderr, "new passphrase for %s: ", keyPath)
	p, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "again: ")
	q, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	defer clear(q)
	if err != nil {
		clear(p)
		return nil, err
	}
	if !bytes.Equal(p, q) {
		clear(p)
		return nil, fmt.Errorf("the two passphrases differ; nothing was written")
	}
	if len(p) == 0 {
		return nil, fmt.Errorf("an empty passphrase encrypts nothing; run keygen without --encrypt for a plain key")
	}
	return p, nil
}
