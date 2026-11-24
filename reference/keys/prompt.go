package keys

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"

	"golang.org/x/term"
)

// EnvPassphrase is the environment variable the reference CLIs read a key's passphrase from, for CI
// and scripts. TakeEnvPassphrase reads and unsets it; it is never set or logged.
const EnvPassphrase = "KTON_KEY_PASSPHRASE"

var (
	envMu   sync.Mutex
	envPass []byte
	envSet  bool
)

// TakeEnvPassphrase reads $KTON_KEY_PASSPHRASE and unsets it, so processes started later do not
// inherit it (kton-review K3 on #277). It cannot hide the start value: on Linux /proc/<pid>/environ
// keeps the environment the process started with, readable by the same user and root. A program calls it first thing in main;
// CLIPassphrase and NewPassphrase call it too, so a caller that forgets still unsets it on first use.
// The value is held for later keys; a value set again later replaces it. The returned slice is a copy.
func TakeEnvPassphrase() ([]byte, bool) {
	envMu.Lock()
	defer envMu.Unlock()
	if p, ok := os.LookupEnv(EnvPassphrase); ok {
		clear(envPass)
		envPass, envSet = []byte(p), true
		os.Unsetenv(EnvPassphrase)
	}
	if !envSet {
		return nil, false
	}
	return bytes.Clone(envPass), true
}

// ForgetEnvPassphrase overwrites and drops the passphrase TakeEnvPassphrase holds. A program that has
// loaded its keys can call it; a later encrypted key then needs the terminal or the variable again.
func ForgetEnvPassphrase() {
	envMu.Lock()
	defer envMu.Unlock()
	clear(envPass)
	envPass, envSet = nil, false
}

// Terminal is the console a passphrase is asked on: in for reading (no echo), out for the prompt.
type Terminal struct {
	In  *os.File
	Out io.Writer
}

// OpenTerminal opens the controlling terminal: /dev/tty, or CONIN$ on Windows. It is not stdin, so
// a passphrase is asked of the person even when stdin carries data. A variable, so a test or a
// caller with its own console can replace it.
var OpenTerminal = func() (Terminal, func(), error) {
	if runtime.GOOS == "windows" {
		in, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
		if err != nil {
			return Terminal{}, nil, err
		}
		return Terminal{In: in, Out: os.Stderr}, func() { in.Close() }, nil
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return Terminal{}, nil, err
	}
	return Terminal{In: tty, Out: tty}, func() { tty.Close() }, nil
}

func ask(t Terminal, prompt string) ([]byte, error) {
	fmt.Fprint(t.Out, prompt)
	p, err := term.ReadPassword(int(t.In.Fd()))
	fmt.Fprintln(t.Out)
	return p, err
}

func terminal() (Terminal, func(), error) {
	t, closeFn, err := OpenTerminal()
	if err == nil && !term.IsTerminal(int(t.In.Fd())) {
		closeFn()
		err = fmt.Errorf("not a terminal")
	}
	return t, closeFn, err
}

// CLIPassphrase is the Passphrase the reference CLIs use: $KTON_KEY_PASSPHRASE if it was set (read
// once, then unset), else a prompt on the controlling terminal with no echo. Without either it
// refuses and says how to supply one; it never takes a passphrase from argv or a file.
func CLIPassphrase(keyPath string) ([]byte, error) {
	if p, ok := TakeEnvPassphrase(); ok {
		return p, nil
	}
	t, closeFn, err := terminal()
	if err != nil {
		return nil, fmt.Errorf("the key is encrypted and there is no terminal to ask for its "+
			"passphrase: set %s", EnvPassphrase)
	}
	defer closeFn()
	return ask(t, "passphrase for "+keyPath+": ")
}

// NewPassphrase is how keygen --encrypt gets a passphrase: $KTON_KEY_PASSPHRASE if it was set, else
// asked twice on the controlling terminal, and the two must match. An empty passphrase is refused.
func NewPassphrase(keyPath string) ([]byte, error) {
	if p, ok := TakeEnvPassphrase(); ok {
		if len(p) == 0 {
			return nil, fmt.Errorf("%s is set but empty: an empty passphrase encrypts nothing", EnvPassphrase)
		}
		return p, nil
	}
	t, closeFn, err := terminal()
	if err != nil {
		return nil, fmt.Errorf("no terminal to ask for a passphrase for %s: set %s", keyPath, EnvPassphrase)
	}
	defer closeFn()
	p, err := ask(t, "new passphrase for "+keyPath+": ")
	if err != nil {
		return nil, err
	}
	q, err := ask(t, "again: ")
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
