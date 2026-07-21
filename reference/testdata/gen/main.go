// Command gen regenerates the frozen conformance vectors in ../ (reference/testdata) from the
// human-readable *.statement.json sources, signing each with a DETERMINISTIC test key derived
// from a public label (no secret material is committed; the keys are reproducible from source).
//
// This is the frozen cross-implementation contract: a second implementation must reproduce the
// same canonical payload, foton id, and action key. Run from the reference module dir:
//
//	go run ./testdata/gen
//
// (testdata/ is ignored by `go build ./...`, so this tool never ships in the library.)
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"kton.dev/plankton/core"
)

func keyFromLabel(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func keyid(pub ed25519.PublicKey) string {
	s := sha256.Sum256(pub)
	return hex.EncodeToString(s[:])[:16]
}

func regen(stPath, dssePath, pubPath string, priv ed25519.PrivateKey) []byte {
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
	if err := os.WriteFile(pubPath, []byte(hex.EncodeToString(priv.Public().(ed25519.PublicKey))), 0o644); err != nil {
		panic(err)
	}
	return payload
}

func main() {
	d := "testdata/"
	author := keyFromLabel("kton.dev/testvector/foton-author/v1")
	confirmer := keyFromLabel("kton.dev/testvector/verdict-confirmer/v1")
	fp := regen(d+"foton.statement.json", d+"foton.dsse.json", d+"author.pub", author)
	regen(d+"verdict.statement.json", d+"verdict.dsse.json", d+"confirmer.pub", confirmer)

	var st core.Statement
	if err := json.Unmarshal(fp, &st); err != nil {
		panic(err)
	}
	f, err := st.ToFoton()
	if err != nil {
		panic(err)
	}
	id, _ := f.FotonID()
	ak, _ := f.ActionKey()
	fmt.Printf("FOTON_ID       %s\n", id)
	fmt.Printf("ACTION_KEY     %s\n", ak)
	fmt.Printf("AUTHOR_KEYID   %s\n", keyid(author.Public().(ed25519.PublicKey)))
	fmt.Printf("CONFIRMER_KEYID %s\n", keyid(confirmer.Public().(ed25519.PublicKey)))
}
