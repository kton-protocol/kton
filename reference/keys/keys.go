// Package keys reads and writes a signer's Ed25519 private key file (#277).
//
// Two forms are read:
//
//   - the plain form keygen has always written: the 32-byte seed as hex, nothing else;
//   - the OpenSSH private-key form ("-----BEGIN OPENSSH PRIVATE KEY-----"), Ed25519 only,
//     unencrypted or encrypted with a passphrase (bcrypt_pbkdf and AES-256-CTR), as
//     `ssh-keygen -t ed25519` writes it and `ssh-keygen -p` re-encrypts it (openssh.go).
//
// Both hold the same seed, so a key keeps its keyid whichever form it is in.
//
// This is how a signer reads its OWN key. Nothing here is protocol: verification, the SPEC and the
// store are unchanged, and kton still grants no permissions. Where the passphrase comes from is the
// caller's decision, through a Passphrase callback; this package never reads one from argv or a
// file. The package is separate from core so that core, and every package a verifier uses, stays free of
// dependencies (K8 on #277): only signing pulls in golang.org/x/crypto/blowfish.
package keys

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
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
	defer clear(b)
	k, err := Parse(b, path, pass)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return k, nil
}

// Parse is Load on bytes already read. keyPath is only passed on to pass, to say which key is meant.
// An error never carries bytes of b.
func Parse(b []byte, keyPath string, pass Passphrase) (ed25519.PrivateKey, error) {
	return parse(b, keyPath, pass, MaxRounds)
}

func parse(b []byte, keyPath string, pass Passphrase, maxRounds int) (ed25519.PrivateKey, error) {
	if !IsPEM(b) {
		return parseHex(b)
	}
	f, err := readSSHFile(b, maxRounds)
	if err != nil {
		return nil, err
	}
	if !f.encrypted() {
		return f.open(nil)
	}
	if pass == nil {
		return nil, ErrNoPassphrase
	}
	p, err := pass(keyPath)
	if err != nil {
		return nil, err
	}
	defer clear(p)
	return f.open(p)
}

func parseHex(b []byte) (ed25519.PrivateKey, error) {
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	defer clear(seed)
	if err != nil {
		// hex's error quotes the offending byte; this one does not (K4).
		return nil, errors.New("neither a hex seed nor an OpenSSH private key")
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("expected %d-byte seed, got %d", ed25519.SeedSize, len(seed))
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// PublicKey returns the public half of a key file's bytes without a passphrase: the plain form
// derives it from the seed, and the OpenSSH form stores it unencrypted next to the encrypted part.
// keyid and pubkey use it, so naming a key never asks for its passphrase. For an encrypted key the
// stored half is not checked against the private one until the key is loaded (K5 in Load).
func PublicKey(b []byte) (ed25519.PublicKey, error) {
	if !IsPEM(b) {
		k, err := parseHex(b)
		if err != nil {
			return nil, err
		}
		defer clear(k)
		return k.Public().(ed25519.PublicKey), nil
	}
	f, err := readSSHFile(b, MaxRounds)
	if err != nil {
		return nil, err
	}
	if !f.encrypted() {
		k, err := f.open(nil)
		if err != nil {
			return nil, err
		}
		defer clear(k)
	}
	return f.pub, nil
}

// IsPEM says whether b is PEM-armoured (read as the OpenSSH form, any other PEM refused) rather than
// the plain hex seed.
func IsPEM(b []byte) bool {
	return strings.HasPrefix(strings.TrimSpace(string(b)), "-----BEGIN ")
}

// IsEncrypted says whether b is an OpenSSH key that needs a passphrase.
func IsEncrypted(b []byte) bool {
	if !IsPEM(b) {
		return false
	}
	f, err := readSSHFile(b, MaxRounds)
	return err == nil && f.encrypted()
}

// MarshalEncrypted writes priv in the OpenSSH form, encrypted with passphrase (aes256-ctr, bcrypt
// with 24 rounds, as ssh-keygen does). Each call draws a fresh salt, so two calls on the same key
// give different bytes that decrypt to the same seed.
func MarshalEncrypted(priv ed25519.PrivateKey, passphrase []byte) ([]byte, error) {
	return marshalOpenSSH(priv, passphrase, writeRounds)
}
