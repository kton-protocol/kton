// Package keys reads and writes a signer's Ed25519 private key file (#277).
//
// Two forms are read:
//
//   - the plain form keygen has always written: the 32-byte seed as hex, nothing else;
//   - the OpenSSH private-key form ("-----BEGIN OPENSSH PRIVATE KEY-----"), unencrypted or
//     encrypted with a passphrase (bcrypt-pbkdf and AES-256-CTR), as `ssh-keygen -t ed25519`
//     writes it and `ssh-keygen -p` re-encrypts it.
//
// Both hold the same seed, so a key keeps its keyid whichever form it is in.
//
// This is how a signer reads its OWN key. Nothing here is protocol: verification, the SPEC and the
// store are unchanged, and kton still grants no permissions. Where the passphrase comes from is the
// caller's decision, through a Passphrase callback; this package never reads one from argv or a
// file. The package is separate from core so that core stays free of dependencies.
package keys

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Passphrase returns the passphrase for the encrypted key file at keyPath. It is called only when
// the file is encrypted. The returned slice is overwritten with zeros after use.
type Passphrase func(keyPath string) ([]byte, error)

// ErrNoPassphrase is returned for an encrypted key when there is no Passphrase to ask.
var ErrNoPassphrase = errors.New("the key file is encrypted and no passphrase source was given")

// ErrWrongPassphrase is returned when the passphrase does not decrypt the key.
var ErrWrongPassphrase = errors.New("wrong passphrase")

// Load reads the private key at path in either form. pass is consulted only for an encrypted key;
// it may be nil when the caller has no way to ask.
func Load(path string, pass Passphrase) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k, err := Parse(b, path, pass)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return k, nil
}

// Parse is Load on bytes already read. keyPath is only passed on to pass, to say which key is meant.
func Parse(b []byte, keyPath string, pass Passphrase) (ed25519.PrivateKey, error) {
	if !IsPEM(b) {
		seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil {
			return nil, fmt.Errorf("neither a hex seed nor an OpenSSH private key: %v", err)
		}
		if len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("expected %d-byte seed, got %d", ed25519.SeedSize, len(seed))
		}
		return ed25519.NewKeyFromSeed(seed), nil
	}
	k, err := ssh.ParseRawPrivateKey(b)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		if pass == nil {
			return nil, ErrNoPassphrase
		}
		p, perr := pass(keyPath)
		if perr != nil {
			return nil, perr
		}
		k, err = ssh.ParseRawPrivateKeyWithPassphrase(b, p)
		clear(p)
		if errors.Is(err, x509.IncorrectPasswordError) {
			return nil, ErrWrongPassphrase
		}
	}
	if err != nil {
		return nil, err
	}
	return ed25519Of(k)
}

// PublicKey returns the public half of a key file's bytes without a passphrase: the plain form
// derives it from the seed, and the OpenSSH form stores it unencrypted next to the encrypted part.
// keyid and pubkey use it, so naming a key never asks for its passphrase.
func PublicKey(b []byte) (ed25519.PublicKey, error) {
	if !IsPEM(b) {
		k, err := Parse(b, "", nil)
		if err != nil {
			return nil, err
		}
		return k.Public().(ed25519.PublicKey), nil
	}
	k, err := ssh.ParseRawPrivateKey(b)
	var missing *ssh.PassphraseMissingError
	switch {
	case errors.As(err, &missing):
		if missing.PublicKey == nil {
			return nil, fmt.Errorf("the encrypted key does not carry its public key")
		}
		ck, ok := missing.PublicKey.(ssh.CryptoPublicKey)
		if !ok {
			return nil, fmt.Errorf("not an Ed25519 key (%s)", missing.PublicKey.Type())
		}
		pub, ok := ck.CryptoPublicKey().(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("not an Ed25519 key (%s)", missing.PublicKey.Type())
		}
		return pub, nil
	case err != nil:
		return nil, err
	}
	priv, err := ed25519Of(k)
	if err != nil {
		return nil, err
	}
	return priv.Public().(ed25519.PublicKey), nil
}

// IsPEM says whether b is a PEM-armoured key (the OpenSSH form) rather than the plain hex seed.
func IsPEM(b []byte) bool {
	return strings.HasPrefix(strings.TrimSpace(string(b)), "-----BEGIN ")
}

// IsEncrypted says whether b is a key that needs a passphrase.
func IsEncrypted(b []byte) bool {
	if !IsPEM(b) {
		return false
	}
	_, err := ssh.ParseRawPrivateKey(b)
	var missing *ssh.PassphraseMissingError
	return errors.As(err, &missing)
}

// MarshalEncrypted writes priv in the OpenSSH form, encrypted with passphrase. Each call draws a
// fresh salt, so two calls on the same key give different bytes that decrypt to the same seed.
func MarshalEncrypted(priv ed25519.PrivateKey, passphrase []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("an empty passphrase encrypts nothing")
	}
	blk, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", passphrase)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(blk), nil
}

func ed25519Of(k any) (ed25519.PrivateKey, error) {
	switch kk := k.(type) {
	case *ed25519.PrivateKey:
		return *kk, nil
	case ed25519.PrivateKey:
		return kk, nil
	default:
		return nil, fmt.Errorf("not an Ed25519 key (%T); kton signs with Ed25519 only", k)
	}
}
