package keys

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pubOfSSH reads an ssh-keygen .pub line ("ssh-ed25519 <base64 blob> comment") by hand, so the
// tests need no SSH library either.
func pubOfSSH(t *testing.T, path string) ed25519.PublicKey {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Fields(string(b))
	if len(f) < 2 || f[0] != keyTypeEd {
		t.Fatalf("%s: not an ssh-ed25519 public key line", path)
	}
	blob, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil {
		t.Fatal(err)
	}
	pub, err := readEdPublic(blob)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func fixed(p string) Passphrase {
	return func(string) ([]byte, error) { return []byte(p), nil }
}

// The plain form keygen has always written is read exactly as before.
func TestLoadPlainHexSeed(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	f := filepath.Join(t.TempDir(), "a.key")
	os.WriteFile(f, []byte(hex.EncodeToString(priv.Seed())+"\n"), 0o600)
	asked := false
	got, err := Load(f, func(string) ([]byte, error) { asked = true; return nil, nil })
	if err != nil || !bytes.Equal(got, priv) {
		t.Fatalf("Load = %v, %v", got, err)
	}
	if asked {
		t.Error("a plain key asked for a passphrase")
	}
	if pub, err := PublicKey([]byte(hex.EncodeToString(priv.Seed()))); err != nil || !bytes.Equal(pub, priv.Public().(ed25519.PublicKey)) {
		t.Errorf("PublicKey = %v, %v", pub, err)
	}
	if _, err := Parse([]byte("abcd"), "", nil); err == nil {
		t.Error("a short seed was accepted")
	}
}

// Keys made by ssh-keygen: unencrypted, and encrypted with a passphrase.
func TestLoadOpenSSHFromSSHKeygen(t *testing.T) {
	want := pubOfSSH(t, "testdata/plain-openssh.key.pub")
	got, err := Load("testdata/plain-openssh.key", nil)
	if err != nil || !bytes.Equal(got.Public().(ed25519.PublicKey), want) {
		t.Fatalf("unencrypted: %v", err)
	}

	want = pubOfSSH(t, "testdata/encrypted.key.pub")
	b, _ := os.ReadFile("testdata/encrypted.key")
	if !IsEncrypted(b) {
		t.Error("IsEncrypted = false for an encrypted key")
	}
	if _, err := Load("testdata/encrypted.key", nil); !errors.Is(err, ErrNoPassphrase) {
		t.Errorf("no passphrase source: %v, want ErrNoPassphrase", err)
	}
	if _, err := Load("testdata/encrypted.key", fixed("wrong")); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("wrong passphrase: %v, want ErrWrongPassphrase", err)
	}
	// ssh-keygen at rounds 1, 16, 24 (its default) and 64 (kton-review A2).
	for _, f := range []string{"encrypted-r1.key", "encrypted-r16.key", "encrypted-r64.key"} {
		k, err := Load("testdata/"+f, fixed("correct horse"))
		if err != nil || !bytes.Equal(k.Public().(ed25519.PublicKey), pubOfSSH(t, "testdata/"+f+".pub")) {
			t.Errorf("%s: %v", f, err)
		}
	}
	var askedFor string
	got, err = Load("testdata/encrypted.key", func(p string) ([]byte, error) { askedFor = p; return []byte("correct horse"), nil })
	if err != nil || !bytes.Equal(got.Public().(ed25519.PublicKey), want) {
		t.Fatalf("encrypted: %v", err)
	}
	if askedFor != "testdata/encrypted.key" {
		t.Errorf("the callback was asked about %q", askedFor)
	}
	// Naming the key needs no passphrase: the public half is stored in clear.
	if pub, err := PublicKey(b); err != nil || !bytes.Equal(pub, want) {
		t.Errorf("PublicKey of the encrypted key = %v, %v", pub, err)
	}
	// A failing source is passed through, not mistaken for a wrong passphrase.
	boom := errors.New("no tty")
	if _, err := Load("testdata/encrypted.key", func(string) ([]byte, error) { return nil, boom }); !errors.Is(err, boom) {
		t.Errorf("source error: %v", err)
	}
}

func TestRefusesANonEd25519Key(t *testing.T) {
	if _, err := Load("testdata/rsa.key", nil); err == nil || !strings.Contains(err.Error(), "Ed25519") {
		t.Errorf("rsa: %v", err)
	}
	b, _ := os.ReadFile("testdata/rsa.key")
	if _, err := PublicKey(b); err == nil {
		t.Error("PublicKey accepted an RSA key")
	}
}

// What keygen --encrypt writes holds the same seed, so the keyid does not change, and ssh-keygen can
// read it (checked by hand: `ssh-keygen -y -f` prints the same public key).
func TestMarshalEncryptedRoundTrip(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := MarshalEncrypted(priv, nil); err == nil {
		t.Error("an empty passphrase was accepted")
	}
	a, err := MarshalEncrypted(priv, []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := MarshalEncrypted(priv, []byte("pw"))
	if bytes.Equal(a, b) {
		t.Error("two encryptions gave the same bytes: the salt is not fresh")
	}
	if !strings.HasPrefix(string(a), "-----BEGIN OPENSSH PRIVATE KEY-----") || !IsEncrypted(a) {
		t.Errorf("not an encrypted OpenSSH key:\n%s", a)
	}
	if bytes.Contains(a, []byte(hex.EncodeToString(priv.Seed()))) {
		t.Error("the seed is in the file in clear")
	}
	got, err := Parse(a, "k", fixed("pw"))
	if err != nil || !bytes.Equal(got, priv) {
		t.Fatalf("round trip: %v", err)
	}
	if pub, err := PublicKey(a); err != nil || !bytes.Equal(pub, priv.Public().(ed25519.PublicKey)) {
		t.Errorf("PublicKey: %v", err)
	}
}

func noTerminal(t *testing.T) {
	t.Helper()
	old := OpenTerminal
	OpenTerminal = func() (Terminal, func(), error) { return Terminal{}, nil, errors.New("no tty in this test") }
	t.Cleanup(func() { OpenTerminal = old })
}

// kton-review K3 on #277: the variable is read, then removed from the process environment, so a
// child started after the key loads does not inherit it (a child gets os.Environ()); the value is
// held for the next key, replaced by a later one, and dropped by ForgetEnvPassphrase.
func TestPassphraseFromEnv(t *testing.T) {
	noTerminal(t)
	t.Cleanup(ForgetEnvPassphrase)
	t.Setenv(EnvPassphrase, "correct horse")
	if _, err := Load("testdata/encrypted.key", CLIPassphrase); err != nil {
		t.Fatalf("CLIPassphrase with %s: %v", EnvPassphrase, err)
	}
	if _, ok := os.LookupEnv(EnvPassphrase); ok {
		t.Errorf("%s is still in the environment after the key loaded", EnvPassphrase)
	}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, EnvPassphrase+"=") {
			t.Errorf("os.Environ, what a child inherits, still has %s", EnvPassphrase)
		}
	}
	if _, err := Load("testdata/encrypted.key", CLIPassphrase); err != nil {
		t.Errorf("a second key after the variable was taken: %v", err)
	}
	if p, err := NewPassphrase("x"); err != nil || string(p) != "correct horse" {
		t.Errorf("NewPassphrase: %q %v", p, err)
	}
	t.Setenv(EnvPassphrase, "other")
	if p, _ := TakeEnvPassphrase(); string(p) != "other" {
		t.Errorf("a later value did not replace the held one: %q", p)
	}
	ForgetEnvPassphrase()
	if _, err := Load("testdata/encrypted.key", CLIPassphrase); err == nil || !strings.Contains(err.Error(), EnvPassphrase) {
		t.Errorf("after Forget, no variable and no terminal: %v; want a refusal naming %s", err, EnvPassphrase)
	}
	t.Setenv(EnvPassphrase, "")
	if _, err := NewPassphrase("x"); err == nil {
		t.Error("an empty passphrase from the environment was accepted for a new key")
	}
}

// Asked on the controlling terminal, not stdin: an opened console that is not a terminal is refused,
// and stdin is never read.
func TestPromptNeedsATerminal(t *testing.T) {
	ForgetEnvPassphrase()
	os.Unsetenv(EnvPassphrase)
	r, w, _ := os.Pipe()
	defer w.Close()
	old := OpenTerminal
	OpenTerminal = func() (Terminal, func(), error) { return Terminal{In: r, Out: io.Discard}, func() { r.Close() }, nil }
	defer func() { OpenTerminal = old }()
	if _, err := CLIPassphrase("k"); err == nil {
		t.Error("a pipe was accepted as the terminal")
	}
}
