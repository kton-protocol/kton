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
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--seed":
			i++
			seedHex = arg(args, i)
		default:
			if strings.HasPrefix(args[i], "--") {
				return fmt.Errorf("unknown flag %q", args[i])
			}
			name = args[i]
		}
	}
	if name == "" {
		return fmt.Errorf("usage: %s keygen <name> [--seed <64-hex>]", "nekton")
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

	if err := os.WriteFile(name+".key", []byte(hex.EncodeToString(priv.Seed())), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(name+".pub", []byte(hex.EncodeToString(pub)), 0o644); err != nil {
		return err
	}
	fmt.Printf("keypair %s  keyid=%s\n", name, keyidHex(pub))
	return nil
}

// pubkey prints the public key hex for a private key, so an identity written by hand (or carried as
// a bare seed) can still produce the .pub that verify and --trust-keys read.
func pubkey(arg string) error {
	txt := arg
	if b, err := os.ReadFile(arg); err == nil {
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

func loadPriv(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("expected %d-byte seed, got %d", ed25519.SeedSize, len(seed))
	}
	return ed25519.NewKeyFromSeed(seed), nil
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
func authorClaim(specPath, keyPath, outPath string, addFlag bool, regDir string) error {
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
	return signClaim(spec, priv, outPath, addFlag, regDir)
}

// buildClaimEnv canonicalizes a claimSpec into a signed in-toto Statement (SPEC §7.3) and returns the
// envelope JSON bytes plus the claim id. The one signing path, shared by the file and --add forms.
func buildClaimEnv(spec claimSpec, priv ed25519.PrivateKey) ([]byte, string, error) {
	env, id, err := claim.SignWith(spec, priv)
	if err != nil {
		return nil, "", err
	}
	// Marshalled through a map rather than the core.Envelope struct on purpose: a map marshals its
	// keys alphabetically, which is the on-disk key order this command has always written. Emitting
	// the struct instead would reorder the file (payloadType before payload) - harmless to any
	// verifier, but a gratuitous diff in every committed .dsse.json and example snapshot.
	out, err := json.MarshalIndent(map[string]any{
		"payloadType": env.PayloadType,
		"payload":     env.Payload,
		"signatures": []any{map[string]any{
			"keyid": env.Signatures[0].KeyID,
			"sig":   env.Signatures[0].Sig,
		}},
	}, "", "  ")
	if err != nil {
		return nil, "", err
	}
	return out, id, nil
}

// signClaim builds the claim, writes the envelope to outPath (unless --add was given without an
// explicit -o), and optionally ingests it into a registry. Shared by `nekton claim` and `nekton
// annotate`.
func signClaim(spec claimSpec, priv ed25519.PrivateKey, outPath string, addFlag bool, regDir string) error {
	b, id, err := buildClaimEnv(spec, priv)
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
	fmt.Printf("claim %s  keyid=%s  %s\n", id, keyidHex(priv.Public().(ed25519.PublicKey)), dest)
	if addFlag {
		var env core.Envelope
		if err := json.Unmarshal(b, &env); err != nil {
			return err
		}
		r, err := registry.Open(regOrDefault(regDir))
		if err != nil {
			return err
		}
		rid, isNew, err := r.Add(env)
		if err != nil {
			return err
		}
		if isNew {
			fmt.Printf("indexed claim %s  (registry now holds %d claims)\n", rid, r.Len())
		} else {
			fmt.Printf("already present: claim %s\n", rid)
		}
	}
	return nil
}
