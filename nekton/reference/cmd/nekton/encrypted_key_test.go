package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kton.dev/plankton/keys"
)

// #277: keygen --encrypt writes an encrypted OpenSSH key with the same keyid as its .pub; signing
// reads it with the passphrase from KTON_KEY_PASSPHRASE; keyid and pubkey name it without one.
func TestKeygenEncrypt(t *testing.T) {
	name := filepath.Join(t.TempDir(), "alice")
	if err := keygen([]string{name, "--encrypt", "--seed", strings.Repeat("ab", 32)}); err == nil {
		t.Error("--encrypt with --seed was accepted")
	}
	t.Setenv(keys.EnvPassphrase, "s3cret pass")
	if err := keygen([]string{name, "--encrypt"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(name + ".key")
	if !keys.IsEncrypted(b) {
		t.Fatalf("keygen --encrypt wrote no encrypted key:\n%s", b)
	}
	fromPub, err := keyidOf(name + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(keys.EnvPassphrase, "wrong")
	fromKey, err := keyidOf(name + ".key")
	if err != nil || fromKey != fromPub {
		t.Errorf("keyid of the encrypted .key = %q (%v), of the .pub = %q", fromKey, err, fromPub)
	}
	if _, err := loadPriv(name + ".key"); err == nil {
		t.Error("a wrong passphrase loaded the key")
	}
	t.Setenv(keys.EnvPassphrase, "s3cret pass")
	priv, err := loadPriv(name + ".key")
	if err != nil {
		t.Fatal(err)
	}
	if keyidHex(priv.Public().(ed25519.PublicKey)) != fromPub {
		t.Error("the decrypted key is not the .pub's key")
	}
	// Re-running keygen refuses as before: the file holds a different (freshly salted) content.
	if err := keygen([]string{name, "--encrypt"}); err == nil {
		t.Error("keygen overwrote an existing key")
	}
}

// Without the variable and without a terminal (as under go test), an encrypted key is refused with
// the way to supply the passphrase, and a plain key still loads.
func TestEncryptedKeyWithoutPassphraseSource(t *testing.T) {
	t.Setenv(keys.EnvPassphrase, "") // restored after the test
	os.Unsetenv(keys.EnvPassphrase)
	name := filepath.Join(t.TempDir(), "bob")
	if err := keygen([]string{name}); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPriv(name + ".key"); err != nil {
		t.Fatalf("a plain key: %v", err)
	}
	if _, err := loadPriv("../../../../reference/keys/testdata/encrypted.key"); err == nil || !strings.Contains(err.Error(), keys.EnvPassphrase) {
		t.Errorf("encrypted, no source: %v; want a refusal naming %s", err, keys.EnvPassphrase)
	}
}
