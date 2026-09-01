package main

// author.go adds the write side the cockpit needs: generate a signing identity (keygen)
// and author + sign a foton (author). (Signed claims - verdict, environment-qualification,
// etc. - moved to the nekton layer in the M1 split; plankton authors only fotons.)
// plankton still does not execute and does not decide whom to trust - it just lets a
// holder of a key produce the signed fotons it will later store and verify. The "Run +
// record" button is exactly: run the executor, then `plankton author` the resulting foton.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"kton.dev/plankton/core"
	"kton.dev/plankton/foton"
	"kton.dev/plankton/registry"
)

// keyidHex matches the Python spike: first 16 hex chars of sha256(rawPublicKey).
func keyidHex(pub ed25519.PublicKey) string {
	s := sha256.Sum256(pub)
	return hex.EncodeToString(s[:])[:16]
}

// keyidOf resolves a .pub/.key file, a raw hex public key, a private-seed .key, or an existing 16-hex
// keyid to the keyid shown in signatures. A private .key (32-byte seed) and a .pub (32-byte public key)
// are both 64 hex; they are told apart by the ".key" suffix (a raw hex string is treated as a pubkey).
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

// keygen writes <name>.key (hex Ed25519 seed) and <name>.pub (hex public key).
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
		return fmt.Errorf("usage: %s keygen <name> [--seed <64-hex>]", "plankton")
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

// The spec types and the payload assembly moved to kton.dev/plankton/foton so that every authoring
// path - this CLI, a cockpit, an executor publishing a run it just performed - goes through one
// implementation. The old names stay as aliases: nothing else in this package moves.
type fileSpec = foton.FileSpec

// splitKV splits "left=right" on the FIRST '=' (so a URI's own '=' stays in the value).
func splitKV(s string) (string, string, bool) {
	if i := strings.IndexByte(s, '='); i >= 0 {
		return s[:i], s[i+1:], true
	}
	return "", "", false
}

type authorSpec = foton.Spec

// author builds an in-toto Statement per the spec, signs a DSSE envelope, and writes it.
// Byte-compatible with the Python spike (canonical JSON + PAE + Ed25519), so the same
// `plankton verify` / `plankton add` accept it.
func author(specPath, keyPath, outPath string) error {
	raw, err := os.ReadFile(specPath)
	if err != nil {
		return err
	}
	spec, err := foton.ParseSpec(raw)
	if err != nil {
		return err
	}
	priv, err := loadPriv(keyPath)
	if err != nil {
		return err
	}
	return signFoton(spec, priv, outPath)
}

// authorConvenience is the flag form: `plankton author --in F --out F --cmd "…" --sign key`.
// It content-addresses files that ALREADY EXIST and RECORDS the protocol descriptor - it does
// NOT run --cmd. plankton documents, it never executes (the command was already run by an
// executor; this just signs the result). Saves a session from pre-hashing + hand-writing JSON.
func authorConvenience(args []string) error {
	var ins, outs []string
	var cmd, keyPath, outPath, env, envRef, regDir string
	kind := "script"
	addFlag := false
	strict := false
	printID := false                 // print ONLY the bare foton id to stdout (human lines go to stderr) - for scripting
	locatedAuto := false             // default a file://<abs> locator for every --in/--out that lacks an explicit --located
	located := map[string][]string{} // logical path -> fetch URIs (CARRIED)
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--add":
			addFlag = true
		case "--registry":
			i++
			if i < len(args) {
				regDir = args[i]
			}
		case "--in":
			i++
			if i < len(args) {
				ins = append(ins, args[i])
			}
		case "--out":
			i++
			if i < len(args) {
				outs = append(outs, args[i])
			}
		case "--cmd":
			i++
			if i < len(args) {
				cmd = args[i]
			}
		case "--kind":
			i++
			if i < len(args) {
				kind = args[i]
			}
		case "--environment", "--env":
			i++
			if i < len(args) {
				env = args[i]
			}
		case "--env-ref":
			i++
			if i < len(args) {
				envRef = args[i]
			}
		case "--sign":
			i++
			if i < len(args) {
				keyPath = args[i]
			}
		case "-o":
			i++
			if i < len(args) {
				outPath = args[i]
			}
		case "--located":
			i++
			if i < len(args) {
				p, u, ok := splitKV(args[i])
				if !ok {
					return fmt.Errorf("--located wants PATH=URI, got %q", args[i])
				}
				if filepath.IsAbs(p) { // match the same cleaning --in/--out apply, so an abs path still binds
					p = filepath.Base(p)
				}
				p = strings.TrimPrefix(filepath.ToSlash(p), "./")
				located[p] = append(located[p], u)
			}
		case "--strict":
			strict = true
		case "--print-id":
			printID = true
		case "--located-auto":
			locatedAuto = true
		default:
			return fmt.Errorf("unknown flag %q", args[i])
		}
	}
	if len(outs) == 0 || cmd == "" {
		return fmt.Errorf("usage: plankton author --in F ... --out F ... --cmd \"…\" [--sign KEY] [--add]\n" +
			"  Records existing files as a signed foton (it never runs --cmd). Pass EVERY input as --in,\n" +
			"  INCLUDING the script/code that produced the output — not just the data. Prefer RELATIVE paths: the\n" +
			"  path you give becomes the file's recorded name; an absolute path is reduced to its basename so\n" +
			"  machine paths never leak into the record.\n" +
			"  more: PATH=F sets the recorded name; --located PATH=URL adds where the bytes live; --strict requires\n" +
			"        relative paths; also --environment sha256: (qualified env-spectrum), --env-ref STRING (exact\n" +
			"        execution env: oci://…@sha256: / nix path / server id, COVERED - pins WHICH env ran), --kind K,\n" +
			"        --registry DIR, -o FILE")
	}
	// resolve each "[PATH=]LOCALFILE": PATH is the logical work-tree path recorded (COVERED); LOCALFILE is
	// only read to hash. Absolute local paths are cleaned to their basename so machine paths neither leak
	// into a portable record nor fork its identity. --located URIs (CARRIED) attach by logical path.
	hashFiles := func(args []string) ([]fileSpec, error) {
		fs := make([]fileSpec, 0, len(args))
		for _, arg := range args {
			logical, local, ok := splitKV(arg)
			if !ok {
				logical, local = arg, arg
				if filepath.IsAbs(local) {
					if strict {
						return nil, fmt.Errorf("--strict: %q is an absolute path; give a logical work-tree path, e.g. --in NAME=%s", local, local)
					}
					logical = filepath.Base(local)
				}
			}
			logical = strings.TrimPrefix(filepath.ToSlash(logical), "./")
			b, err := os.ReadFile(local)
			if err != nil {
				return nil, fmt.Errorf("%s: %w (plankton records existing files; it does not run --cmd)", local, err)
			}
			uri := located[logical]
			if len(uri) == 0 && locatedAuto { // default a file://<abs> locator so a viewer can fetch + re-hash
				if abs, aerr := filepath.Abs(local); aerr == nil {
					uri = []string{"file://" + filepath.ToSlash(abs)}
				}
			}
			fs = append(fs, fileSpec{Path: logical, Hash: core.HashBytes(b), URI: uri})
		}
		return fs, nil
	}
	inFs, err := hashFiles(ins)
	if err != nil {
		return err
	}
	outFs, err := hashFiles(outs)
	if err != nil {
		return err
	}
	spec := authorSpec{Predicate: "foton", Inputs: inFs, Outputs: outFs}
	desc := map[string]any{"cmd": cmd}
	if env != "" {
		if !strings.HasPrefix(env, "sha256:") {
			return fmt.Errorf("--environment must be an env-spectrum id (sha256:…), got %q", env)
		}
		desc["environment"] = env // covered: rides in descriptor -> protocol.ref -> action_key (SPEC §3)
	}
	// --env-ref is an OPTIONAL exact execution-environment reference - a string the substrate does not
	// interpret: a docker digest (oci://…@sha256:…), a nix store path, a run-server id. It is COVERED (it
	// rides in the descriptor -> protocol ref -> foton id), so it PINS which environment produced this
	// foton: two fotons that ran the same cmd in DIFFERENT pinned environments get different ids/refs, and
	// a reproduction `--via` this foton commits to re-executing in THIS environment (cold-session
	// composition-chain: a normalizer/program is only trustworthy if the environment it ran in is pinned,
	// not a mutable path). The env-spectrum (--environment) qualifies it; --env-ref names the exact image.
	if envRef != "" {
		desc["envRef"] = envRef
	}
	spec.Protocol = &foton.ProtocolSpec{Kind: kind, Descriptor: desc}
	priv, ephemeral, err := signingKey(keyPath)
	if err != nil {
		return err
	}
	b, err := buildFotonEnv(spec, priv)
	if err != nil {
		return err
	}
	// Write a file UNLESS --add was given without an explicit -o (then ingest directly, no litter).
	writeFile := outPath != "" || !addFlag
	if outPath == "" {
		outPath = "foton.dsse.json"
	}
	if writeFile {
		if err := os.WriteFile(outPath, b, 0o644); err != nil {
			return err
		}
	}
	kid := keyidHex(priv.Public().(ed25519.PublicKey))
	note := ""
	if ephemeral {
		note = " (ephemeral)"
	}
	if env != "" {
		note += "  env=" + env
	}
	// With --print-id the ONLY thing on stdout is the bare foton id (so `ID=$(plankton author … --print-id)`
	// works); every human line is routed to stderr.
	msg := func(format string, a ...any) {
		if printID {
			fmt.Fprintf(os.Stderr, format, a...)
		} else {
			fmt.Printf(format, a...)
		}
	}
	dest := "-> " + outPath
	if !writeFile {
		dest = "(no -o file written; ingested via --add below)"
	}
	msg("authored foton  in=%d out=%d  kind=%s  keyid=%s%s  %s\n", len(inFs), len(outFs), kind, kid, note, dest)
	// Derive the foton id from the envelope (works with or without --add) so --print-id always has it.
	fid := ""
	{
		var e core.Envelope
		if json.Unmarshal(b, &e) == nil {
			if st, serr := e.Statement(); serr == nil {
				if f, ferr := st.ToFoton(); ferr == nil {
					if x, xerr := f.FotonID(); xerr == nil {
						fid = x
					}
				}
			}
		}
	}
	if addFlag {
		var envelope core.Envelope
		if err := json.Unmarshal(b, &envelope); err != nil {
			return err
		}
		r, err := registry.Open(regOrDefault(regDir))
		if err != nil {
			return err
		}
		id, isNew, err := r.Add(envelope)
		if err != nil {
			return err
		}
		if id != "" {
			fid = id
		}
		if isNew {
			msg("indexed foton %s  (registry now holds %d fotons)\n", id, r.Len())
		} else {
			// A foton is IMMUTABLE and content-addressed: an identical descriptor derives the same id, so a
			// re-run dedups to the existing object (your signature is NOT merged in — the foton keeps its
			// first author). This is correct, not a loss. To record that YOU independently produced this exact
			// result, attest it as a nekton claim whose subject is this foton:
			//   nekton annotate sha256:<this-foton-id> --template reproduces --set level=L0 --set reproducedBy=<yours> --sign <you>.key --add
			msg("already present: foton %s\n", id)
			msg("  (fotons are immutable; an identical run dedups here. To record YOUR independent\n" +
				"   reproduction, sign a nekton `reproduces` claim with this foton id as the subject.)\n")
		}
	}
	if printID {
		fmt.Println(fid) // the one machine-readable line on stdout
	}
	return nil
}

// regOrDefault returns the explicit --registry directory if given, else the default (PLANKTON_DIR or
// ./plankton-data). Used by every command that can add to a registry.
func regOrDefault(explicit string) string {
	if explicit != "" {
		return explicit
	}
	return dir()
}

// signingKey returns the signing identity: the key at keyPath, or - when keyPath is empty - a fresh
// EPHEMERAL key. Signing is mandatory, but handing over a persistent key is not: an unnamed session
// signs with a throwaway identity, so which model/agent produced the record is unlinkable (anonymity
// by default). Trust in a foton comes from RE-RUNNING it, not from the signer. Persistent attribution
// is opt-in via --sign.
func signingKey(keyPath string) (ed25519.PrivateKey, bool, error) {
	if keyPath != "" {
		p, err := loadPriv(keyPath)
		return p, false, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, true, err
}

// signFoton canonicalizes an authorSpec into a signed foton envelope and writes it to outPath.
func signFoton(spec authorSpec, priv ed25519.PrivateKey, outPath string) error {
	b, err := buildFotonEnv(spec, priv)
	if err != nil {
		return err
	}
	return os.WriteFile(outPath, b, 0o644)
}

// buildFotonEnv signs the spec through the kernel and returns the envelope in the on-disk shape.
// Shared by signFoton (writes a file) and the --add path (ingests directly, no intermediate file).
func buildFotonEnv(spec authorSpec, priv ed25519.PrivateKey) ([]byte, error) {
	env, _, err := foton.SignWith(spec, priv)
	if err != nil {
		return nil, err
	}
	// Marshalled through a map rather than the core.Envelope struct on purpose: a map marshals its
	// keys alphabetically, which is the on-disk key order this command has always written. Emitting
	// the struct instead would reorder the file (payloadType before payload) - harmless to any
	// verifier, but a gratuitous diff in every committed .dsse.json and example snapshot.
	return json.MarshalIndent(map[string]any{
		"payloadType": env.PayloadType,
		"payload":     env.Payload,
		"signatures": []any{map[string]any{
			"keyid": env.Signatures[0].KeyID,
			"sig":   env.Signatures[0].Sig,
		}},
	}, "", "  ")
}
