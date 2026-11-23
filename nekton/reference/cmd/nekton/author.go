package main

// author.go is the write side: generate a signing identity (keygen) and author + sign a
// claim (claim). nekton, like plankton, does not decide whom to trust - it lets a key holder
// produce the signed claims it will store, verify, and federate. The wire form is byte-compatible
// with plankton's DSSE (shared `core`: canonical JSON + PAE + Ed25519), so the same trust
// tooling applies to both layers.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"kton.dev/nekton/claim"
	"kton.dev/nekton/registry"
	"kton.dev/plankton/core"
	"kton.dev/plankton/keys"
)

// keyidHex: first 16 hex chars of sha256(rawPublicKey) - identical to plankton (shared identity).
func keyidHex(pub ed25519.PublicKey) string {
	s := sha256.Sum256(pub)
	return hex.EncodeToString(s[:])[:16]
}

// keyidOf resolves a .pub/.key file, a raw hex public key, a private-seed .key, or an existing 16-hex
// keyid to the keyid shown as `by=key:<id>`. A private .key (32-byte seed) and a .pub (32-byte public
// key) are both 64 hex; they are told apart by the ".key" suffix (a raw hex string is treated as a pubkey).
func keyidOf(s string) (string, error) {
	isKey := strings.HasSuffix(s, ".key")
	txt := s
	if b, err := os.ReadFile(s); err == nil {
		if keys.IsPEM(b) { // an OpenSSH key, encrypted or not: its public half needs no passphrase
			pub, err := keys.PublicKey(b)
			if err != nil {
				return "", fmt.Errorf("%s: %w", s, err)
			}
			return keyidHex(pub), nil
		}
		txt = string(b)
	}
	txt = strings.TrimSpace(txt)
	if len(txt) == 16 { // already a keyid
		return txt, nil
	}
	raw, err := hex.DecodeString(txt)
	if err != nil {
		return "", fmt.Errorf("not a key: expected a .pub/.key file or hex public key, got %q", s)
	}
	if isKey && len(raw) == ed25519.SeedSize {
		return keyidHex(ed25519.NewKeyFromSeed(raw).Public().(ed25519.PublicKey)), nil
	}
	if len(raw) == ed25519.PublicKeySize {
		return keyidHex(ed25519.PublicKey(raw)), nil
	}
	return "", fmt.Errorf("not an Ed25519 public key or .key seed: %q", s)
}

// keygen writes <name>.key (the 32-byte seed, hex) and <name>.pub (the public key, hex).
//
// --seed makes the identity a function of its input instead of the entropy pool. That matters for
// the same reason --when does (#42): the public key is inside every signed payload - example 07
// even mints an identity IRI from sha256(pub) - so a random key per run moves every record id, and
// a corpus or a snapshot can never be rebuilt to the same bytes. A hand-written seed was already
// accepted as a .key; what was missing was any way back to the .pub hex that verify, --trust-keys
// and the viewer key directories need.
//
// A --seed key is exactly as strong as the seed behind it. Use it for fixtures and reproducible
// corpora, not for an identity that signs anything anyone must trust.
func keygen(args []string) error {
	var name, seedHex string
	force, encrypt := false, false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--encrypt":
			encrypt = true
		case "--seed":
			i++
			seedHex = arg(args, i)
		case "--force":
			force = true
		default:
			if strings.HasPrefix(args[i], "--") {
				return fmt.Errorf("unknown flag %q", args[i])
			}
			name = args[i]
		}
	}
	if name == "" {
		return fmt.Errorf("usage: nekton keygen <name> [--encrypt] [--seed <64-hex>] [--force]")
	}
	// --seed is for fixtures and reproducible corpora: a key that anyone can rebuild from its seed
	// is not protected by encrypting the file, and the fresh salt would make a re-run differ.
	if encrypt && seedHex != "" {
		return fmt.Errorf("--encrypt and --seed together: a --seed key is a fixture, rebuilt from its seed;\n" +
			"  encrypting its file protects nothing")
	}

	var pub ed25519.PublicKey
	var priv ed25519.PrivateKey
	if seedHex == "" {
		var err error
		if pub, priv, err = ed25519.GenerateKey(rand.Reader); err != nil {
			return err
		}
	} else {
		seed, err := hex.DecodeString(strings.TrimSpace(seedHex))
		if err != nil || len(seed) != ed25519.SeedSize {
			return fmt.Errorf("--seed must be %d hex-encoded bytes (%d hex chars), got %q",
				ed25519.SeedSize, ed25519.SeedSize*2, seedHex)
		}
		priv = ed25519.NewKeyFromSeed(seed)
		pub = priv.Public().(ed25519.PublicKey)
	}

	// core.WriteKeyFile refuses to overwrite an identity and creates with the mode it asks for -
	// os.WriteFile's mode applies only to a NEW file, so an existing 0644 key file kept 0644 and
	// took the new private seed. The public half is written second, and a failure there
	// removes the private half rather than leaving a keypair whose public key nobody has.
	// --encrypt (#277): the OpenSSH private-key form, encrypted with a passphrase from
	// $KTON_KEY_PASSPHRASE or asked twice on the terminal. ssh-keygen -p changes it later. The seed,
	// and so the keyid, is the same as in the plain form.
	content := []byte(hex.EncodeToString(priv.Seed()))
	if encrypt {
		pass, err := keys.NewPassphrase(name + ".key")
		if err != nil {
			return err
		}
		content, err = keys.MarshalEncrypted(priv, pass)
		clear(pass)
		if err != nil {
			return err
		}
	}
	kw, err := core.WriteKeyFile(name+".key", content, 0o600, force)
	if err != nil {
		return err
	}
	if _, err := core.WriteKeyFile(name+".pub", []byte(hex.EncodeToString(pub)), 0o644, force); err != nil {
		// Undo only what THIS call did. Removing name+".key" unconditionally would destroy a private
		// key that was already there - the exact loss the refusal above exists to prevent.
		kw.Undo(name + ".key")
		if kw.Created || kw.Backup != "" {
			return fmt.Errorf("wrote %s.key but could not write %s.pub, so the private half was rolled back\n"+
				"  rather than left without its public key: %w", name, name, err)
		}
		return fmt.Errorf("could not write %s.pub; the existing %s.key was already this key and is UNTOUCHED: %w",
			name, name, err)
	}
	// The private key's protection is a FILE MODE, and a file mode is a request the platform may
	// decline. On Windows a 0600 request lands as 0666 and every statement this project makes about
	// private keys being unreadable by other users is false there. Saying so at keygen time is the
	// only moment the operator can still act on it.
	if kw.ModeUnenforced != 0 {
		fmt.Fprintf(os.Stderr,
			"warning: %s.key was created with mode %v, not the 0600 that was requested - this\n"+
				"  platform or filesystem does not enforce it (Windows, FAT/exFAT, some network mounts).\n"+
				"  The private key is NOT protected by file permissions here. Restrict access by other\n"+
				"  means (an ACL, a container, an encrypted volume) or generate the key elsewhere.\n",
			name, kw.ModeUnenforced)
	}
	fmt.Printf("keypair %s  keyid=%s\n", name, keyidHex(pub))
	return nil
}

// pubkey prints the public key hex for a private key, so an identity written by hand (or carried as
// a bare seed) can still produce the .pub that verify and --trust-keys read.
func pubkey(arg string) error {
	txt := arg
	if b, err := os.ReadFile(arg); err == nil {
		if keys.IsPEM(b) { // an OpenSSH key: the public half is stored in clear, no passphrase asked
			pub, err := keys.PublicKey(b)
			if err != nil {
				return fmt.Errorf("%s: %w", arg, err)
			}
			fmt.Println(hex.EncodeToString(pub))
			return nil
		}
		txt = string(b)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(txt))
	if err != nil || len(seed) != ed25519.SeedSize {
		return fmt.Errorf("not a %d-byte hex seed (a .key file or the hex itself): %q", ed25519.SeedSize, arg)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	fmt.Println(hex.EncodeToString(pub))
	return nil
}

// loadPubArg accepts a public key as EITHER a .pub file path OR the hex string itself
// (cycle-1 finding: users pasted `$(cat key.pub)` into the "<pubkey.hex>" slot).
func loadPubArg(s string) (ed25519.PublicKey, error) {
	txt := s
	if b, err := os.ReadFile(s); err == nil {
		txt = string(b)
	}
	return core.ParsePublicKeyHex(strings.TrimSpace(txt))
}

// keyidFromArg normalizes a signer argument to a keyid: it accepts a 16-hex keyid as-is, or a
// .pub file / 64-hex public key which it hashes to the keyid (cycle-1 finding: `by signer`
// silently returned nothing when handed a public key instead of the keyid).
func keyidFromArg(s string) string {
	txt := s
	if b, err := os.ReadFile(s); err == nil {
		txt = string(b)
	}
	txt = strings.TrimSpace(txt)
	if len(txt) == 16 {
		return txt
	}
	if pub, err := core.ParsePublicKeyHex(txt); err == nil {
		return keyidHex(pub)
	}
	return strings.TrimSpace(s)
}

// loadPriv reads a signer's key file: the plain hex seed, or the OpenSSH form, encrypted or not
// (#277). An encrypted key's passphrase comes from $KTON_KEY_PASSPHRASE or the terminal, never argv.
func loadPriv(path string) (ed25519.PrivateKey, error) {
	return keys.Load(path, keys.CLIPassphrase)
}

// signingKey returns the signing identity: the key at keyPath, or - when keyPath is empty - a fresh
// EPHEMERAL key. Signing is mandatory, but handing over a persistent key is not: an unnamed session
// signs with a throwaway identity, so which model/agent authored the claim is unlinkable (anonymity
// by default). Persistent attribution is opt-in via --sign; a durable, identity-bearing signature is
// a cockpit concern (kton: Sigstore/OIDC), not a kernel one.
func signingKey(keyPath string) (ed25519.PrivateKey, bool, error) {
	if keyPath != "" {
		p, err := loadPriv(keyPath)
		return p, false, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, true, err
}

// The claim-spec types and the spec -> canonical-Statement assembly now live in the `claim`
// kernel package (claim/spec.go), so the CLI and the browser WASM signer share one
// implementation and therefore produce identical claim ids. These aliases/shims keep the
// existing CLI and test call sites unchanged.
type claimSpec = claim.Spec
type subjSpec = claim.SubjectSpec

func subjectsOf(ss []subjSpec) []any { return claim.SubjectsOf(ss) }
func bareHash(h string) string       { return claim.BareHash(h) }

// authorClaim builds an in-toto Statement per SPEC §7.3, signs a DSSE envelope, and writes it.
func authorClaim(specPath, keyPath, outPath string, addFlag bool, regDir string, printID bool) error {
	raw, err := os.ReadFile(specPath)
	if err != nil {
		return err
	}
	// claim.ParseSpec decodes with UseNumber, so a big integer survives to canonicalization and is
	// REJECTED there rather than being silently truncated through float64 and signed as a different
	// number (cold-session sibling-path finding).
	spec, err := claim.ParseSpec(raw)
	if err != nil {
		return err
	}
	priv, err := loadPriv(keyPath)
	if err != nil {
		return err
	}
	return signClaim(spec, priv, outPath, addFlag, regDir, printID)
}

// buildClaimEnv canonicalizes a claimSpec into a signed in-toto Statement (SPEC §7.3) and returns the
// envelope JSON bytes plus the claim id. The one signing path, shared by the file and --add forms.
func buildClaimEnv(spec claimSpec, priv ed25519.PrivateKey) ([]byte, string, error) {
	env, id, err := claim.SignWith(spec, priv)
	if err != nil {
		return nil, "", err
	}
	b, err := envelopeJSON(env)
	return b, id, err
}

// envelopeJSON is the on-disk form of a signed envelope this command has always written.
func envelopeJSON(env core.Envelope) ([]byte, error) {
	// Marshalled through a map rather than the core.Envelope struct on purpose: a map marshals its
	// keys alphabetically, which is the on-disk key order this command has always written.
	return json.MarshalIndent(map[string]any{
		"payloadType": env.PayloadType,
		"payload":     env.Payload,
		"signatures": []any{map[string]any{
			"keyid": env.Signatures[0].KeyID,
			"sig":   env.Signatures[0].Sig,
		}},
	}, "", "  ")
}

// signClaim builds the claim, writes the envelope to outPath (unless --add was given without an
// explicit -o), and optionally ingests it into a registry. Shared by `nekton claim`, `nekton
// annotate` and `nekton seed`.
//
// printID follows `plankton author --print-id` exactly (main.go:33): the ONLY thing on stdout is the
// bare claim id, every human line goes to stderr. Without it a caller has to parse an identifier out
// of prose - the cockpit was anchoring on the "indexed claim" line, a dependency on output
// formatting that nothing guaranteed and no test protected (#56).
func signClaim(spec claimSpec, priv ed25519.PrivateKey, outPath string, addFlag bool, regDir string, printID bool) error {
	msg := humanOut(printID)
	var env core.Envelope
	var id string
	var w registry.Written
	if addFlag {
		// Writing INTO a store: where the claim goes is part of what is signed, so the store places it
		// (a claim without a scope chains under the root, a new seed hangs off it, #213), and only the
		// scope files the write touches are read, not the whole store (#248).
		var err error
		if w, err = registry.WriteTo(regOrDefault(regDir), spec, priv); err != nil {
			return err
		}
		env, id = w.Envelope, w.ID
		if w.CreatedRoot != "" {
			msg("root %s  (created: this store had none)\n", w.CreatedRoot)
		}
	} else {
		var err error
		if env, id, err = claim.SignWith(spec, priv); err != nil {
			return err
		}
	}
	b, err := envelopeJSON(env)
	if err != nil {
		return err
	}
	writeFile := outPath != "" || !addFlag
	if outPath == "" {
		outPath = "claim.dsse.json"
	}
	if writeFile {
		if err := os.WriteFile(outPath, b, 0o644); err != nil {
			return err
		}
	}
	dest := "-> " + outPath
	if !writeFile {
		dest = "(no -o file written; ingested via --add below)"
	}
	msg("claim %s  keyid=%s  %s\n", id, keyidHex(priv.Public().(ed25519.PublicKey)), dest)
	if addFlag {
		if w.Registered != "" {
			msg("registered in root  (entry %s)\n", w.Registered)
		}
		if w.IsNew {
			msg("indexed claim %s\n", id)
		} else {
			msg("already present: claim %s\n", id)
		}
	}
	if printID {
		fmt.Println(id)
	}
	return nil
}

// humanOut returns the writer for human-readable lines: stderr when the caller asked for a bare id
// on stdout, stdout otherwise. One helper so `claim`, `annotate` and `seed` cannot drift apart on
// which stream a line lands in - a flag that behaves differently on sibling commands is its own trap.
func humanOut(printID bool) func(string, ...any) {
	if printID {
		return func(format string, a ...any) { fmt.Fprintf(os.Stderr, format, a...) }
	}
	return func(format string, a ...any) { fmt.Printf(format, a...) }
}
