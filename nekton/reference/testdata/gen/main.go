// Command gen regenerates the frozen nekton conformance vectors in ../ (nekton/reference/testdata)
// from the human-readable *.statement.json sources, signing each with a DETERMINISTIC test key
// derived from a public label (no secret material is committed; the keys are reproducible from the
// labels below). This mirrors plankton's reference/testdata/gen exactly, one layer up.
//
// This is the frozen cross-implementation contract for SPEC §7: a second implementation MUST
// reproduce the same canonical payload and the same claim id. Run from the reference module dir:
//
//	go run ./testdata/gen
//
// Determinism: fixed ed25519 seeds (from the labels), fixed `when` timestamps baked into the
// source statements, canonical JSON. Running it twice produces byte-identical files.
//
// (testdata/ is ignored by `go build ./...` / `go test ./...`, so this tool never ships in the
// library. The private seeds are TEST KEYS ONLY - never any production identity.)
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"kton.dev/nekton/claim"
	"kton.dev/plankton/core"
)

// keyFromLabel derives a DETERMINISTIC ed25519 test key from a public label (sha256 -> 32-byte
// seed). Identical to plankton's gen: the committed vectors carry only the PUBLIC key; the private
// seed is reproducible from the label and is a TEST KEY, never a real identity.
func keyFromLabel(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(label))
	return ed25519.NewKeyFromSeed(seed[:])
}

// keyid is the nekton/plankton shared keyid: first 16 hex chars of sha256(rawPublicKey).
func keyid(pub ed25519.PublicKey) string {
	s := sha256.Sum256(pub)
	return hex.EncodeToString(s[:])[:16]
}

// regen reads a human-readable Statement, canonicalizes it, signs a DSSE envelope with priv, writes
// the envelope, and returns the claim id (content hash of the canonical Statement, SPEC §3/§7.2).
func regen(stPath, dssePath string, priv ed25519.PrivateKey) string {
	raw, err := os.ReadFile(stPath)
	if err != nil {
		panic(err)
	}
	var st map[string]any
	if err := json.Unmarshal(raw, &st); err != nil {
		panic(err)
	}
	payload, err := core.CanonValue(st)
	if err != nil {
		panic(err)
	}
	sig := ed25519.Sign(priv, core.PAE(core.PayloadType, payload))
	env := map[string]any{
		"payloadType": core.PayloadType,
		"payload":     base64.StdEncoding.EncodeToString(payload),
		"signatures": []any{map[string]any{
			"keyid": keyid(priv.Public().(ed25519.PublicKey)),
			"sig":   base64.StdEncoding.EncodeToString(sig),
		}},
	}
	b, _ := json.MarshalIndent(env, "", "  ")
	if err := os.WriteFile(dssePath, append(b, '\n'), 0o644); err != nil {
		panic(err)
	}
	return claim.ClaimID(payload)
}

func writePub(path string, priv ed25519.PrivateKey) {
	pub := priv.Public().(ed25519.PublicKey)
	if err := os.WriteFile(path, []byte(hex.EncodeToString(pub)), 0o644); err != nil {
		panic(err)
	}
}

func main() {
	d := "testdata/"

	// Fixed test signers (labels -> deterministic ed25519 seeds). TEST KEYS ONLY.
	reviewer := keyFromLabel("kton.dev/testvector/nekton-reviewer/v1") // reviewed + foton-subject
	chair := keyFromLabel("kton.dev/testvector/nekton-chair/v1")       // delegate (governance)
	curator := keyFromLabel("kton.dev/testvector/nekton-curator/v1")   // sameAs (mapping)

	writePub(d+"reviewer.pub", reviewer)
	writePub(d+"chair.pub", chair)
	writePub(d+"curator.pub", curator)

	reviewedID := regen(d+"reviewed.statement.json", d+"reviewed.dsse.json", reviewer)
	delegateID := regen(d+"delegate.statement.json", d+"delegate.dsse.json", chair)
	sameasID := regen(d+"sameas.statement.json", d+"sameas.dsse.json", curator)
	fotonSubjID := regen(d+"foton-subject.statement.json", d+"foton-subject.dsse.json", reviewer)

	fmt.Printf("REVIEWED_CLAIM_ID       %s\n", reviewedID)
	fmt.Printf("DELEGATE_CLAIM_ID       %s\n", delegateID)
	fmt.Printf("SAMEAS_CLAIM_ID         %s\n", sameasID)
	fmt.Printf("FOTON_SUBJECT_CLAIM_ID  %s\n", fotonSubjID)
	fmt.Printf("REVIEWER_KEYID          %s\n", keyid(reviewer.Public().(ed25519.PublicKey)))
	fmt.Printf("CHAIR_KEYID             %s\n", keyid(chair.Public().(ed25519.PublicKey)))
	fmt.Printf("CURATOR_KEYID           %s\n", keyid(curator.Public().(ed25519.PublicKey)))
}
