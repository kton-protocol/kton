package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"kton.dev/plankton/core"
)

// signedLocatedAt builds a signed `located-at` claim record asserting subjectHash -> uri, signed by
// the Ed25519 key derived deterministically from keyLabel. It returns the record as a generic JSON
// map (the shape BuildGraph parses), the signer's public-key hex, and its keyid.
func signedLocatedAt(t *testing.T, keyLabel, subjectHash, uri string) (rec map[string]any, pubHex, keyid string) {
	t.Helper()
	seed := sha256.Sum256([]byte(keyLabel))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)

	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"digest": map[string]any{"sha256": subjectHash}}},
		"predicateType": "https://kton.dev/claim/v0",
		"predicate": map[string]any{
			"predicate": map[string]any{"uri": "https://kton.dev/claim/v0/located-at"},
			"by":        "someone",
			"object":    map[string]any{"uri": uri},
		},
	}
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}
	canon, err := core.CanonJSON(raw)
	if err != nil {
		t.Fatalf("canon: %v", err)
	}
	sig := ed25519.Sign(priv, core.PAE(core.PayloadType, canon))
	rec = map[string]any{
		"claimId": core.HashBytes(canon), // the derived id, so the graph accepts it as authentic-id
		"envelope": map[string]any{
			"payloadType": core.PayloadType,
			"payload":     base64.StdEncoding.EncodeToString(canon),
			"signatures": []any{map[string]any{
				"keyid": core.KeyIDHex(pub),
				"sig":   base64.StdEncoding.EncodeToString(sig),
			}},
		},
	}
	return rec, hex.EncodeToString(pub), core.KeyIDHex(pub)
}

// TestLocatorFoldGatedOnVerification: a located-at claim only injects a retrieval locator when its
// signature VERIFIES against a trusted key. An unverified/planted located-at must NOT put an
// attacker-chosen URI into the locator map (the viewer would present it as "where the bytes live").
// Regression for the previously ungated locator fold.
func TestLocatorFoldGatedOnVerification(t *testing.T) {
	const goodHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const evilHash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const goodURI = "https://good.example/artifact"
	const evilURI = "https://evil.example/pwn"

	trusted, trustedPub, trustedKeyid := signedLocatedAt(t, "trusted-key", goodHash, goodURI)
	planted, _, plantedKeyid := signedLocatedAt(t, "planted-key", evilHash, evilURI)
	if trustedKeyid == plantedKeyid {
		t.Fatal("expected distinct keyids for the two keys")
	}

	union, err := json.Marshal([]any{trusted, planted})
	if err != nil {
		t.Fatalf("marshal union: %v", err)
	}
	// Only the trusted key is in the verifier's key set; the planted signer is unknown → unverified.
	keys, err := json.Marshal(map[string]string{trustedKeyid: trustedPub})
	if err != nil {
		t.Fatalf("marshal keys: %v", err)
	}

	out, err := BuildGraph(string(union), string(keys), "{}")
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}
	var g struct {
		Locators map[string][]string `json:"locators"`
	}
	if err := json.Unmarshal([]byte(out), &g); err != nil {
		t.Fatalf("unmarshal graph: %v", err)
	}

	goodKey := goodHash[:shortLen]
	evilKey := evilHash[:shortLen]
	if got := g.Locators[goodKey]; len(got) != 1 || got[0] != goodURI {
		t.Errorf("verified located-at should fold: Locators[%s] = %v, want [%q]", goodKey, got, goodURI)
	}
	if got := g.Locators[evilKey]; len(got) != 0 {
		t.Errorf("unverified located-at must NOT fold (phishing vector): Locators[%s] = %v, want empty", evilKey, got)
	}
}

// signedClaim builds a signed claim record with an arbitrary subject and object, so a test can
// exercise the subject/object shapes the kernel indexes (hash OR uri) rather than just files.
func signedClaim(t *testing.T, keyLabel, predIRI string, subject, object map[string]any) (rec map[string]any, pubHex, keyid string) {
	t.Helper()
	seed := sha256.Sum256([]byte(keyLabel))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)

	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{subject},
		"predicateType": "https://kton.dev/claim/v0",
		"predicate": map[string]any{
			"predicate": map[string]any{"uri": predIRI},
			"by":        "https://example.org/org/authority",
			"when":      "2026-01-02T03:04:05Z",
			"object":    object,
		},
	}
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}
	canon, err := core.CanonJSON(raw)
	if err != nil {
		t.Fatalf("canon: %v", err)
	}
	sig := ed25519.Sign(priv, core.PAE(core.PayloadType, canon))
	rec = map[string]any{
		"claimId": core.HashBytes(canon),
		"envelope": map[string]any{
			"payloadType": core.PayloadType,
			"payload":     base64.StdEncoding.EncodeToString(canon),
			"signatures": []any{map[string]any{
				"keyid": core.KeyIDHex(pub),
				"sig":   base64.StdEncoding.EncodeToString(sig),
			}},
		},
	}
	return rec, hex.EncodeToString(pub), core.KeyIDHex(pub)
}

// TestURIReferentsBecomeEntities: a claim's subject and object are a hash OR a URI (nekton indexes
// both, and `nekton about`/`nekton by object` resolve both). Reading only `digest.sha256` dropped
// every claim about a person, role, process or period to an unconnected node - the entire
// organisational half of a real graph. Regression for issue #33.
func TestURIReferentsBecomeEntities(t *testing.T) {
	const person = "https://example.org/people/anna"
	const role = "https://example.org/roles/qa-reviewer"
	const fileHash = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

	// person --holds--> role: both ends are IRIs, neither is a file.
	holds, pub, keyid := signedClaim(t, "authority", "http://www.w3.org/ns/org#holds",
		map[string]any{"uri": person}, map[string]any{"id": role})
	// a claim about a FILE whose object is a bare literal: the control. Its subject must still
	// resolve to the content hash, and a literal must NOT become an edge - an attribute stays an
	// attribute, or every status claim turns into a place you can travel to.
	outcome, _, _ := signedClaim(t, "authority", "https://kton.dev/v/outcome",
		map[string]any{"digest": map[string]any{"sha256": fileHash}}, map[string]any{"value": "pass"})

	union, err := json.Marshal([]any{holds, outcome})
	if err != nil {
		t.Fatalf("marshal union: %v", err)
	}
	keys, err := json.Marshal(map[string]string{keyid: pub})
	if err != nil {
		t.Fatalf("marshal keys: %v", err)
	}
	out, err := BuildGraph(string(union), string(keys), "{}")
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}
	var g struct {
		Nodes []struct {
			ID   string `json:"id"`
			Type string `json:"type"`
			Role string `json:"role"`
			URI  string `json:"uri"`
		} `json:"nodes"`
		Edges []struct{ From, To, Kind string } `json:"edges"`
	}
	if err := json.Unmarshal([]byte(out), &g); err != nil {
		t.Fatalf("unmarshal graph: %v", err)
	}

	byID := map[string]string{}      // node id -> type
	entityURI := map[string]string{} // node id -> the IRI it stands for
	labels := map[string]string{}
	for _, n := range g.Nodes {
		byID[n.ID] = n.Type
		if n.Type == "entity" {
			entityURI[n.ID] = n.URI
			labels[n.ID] = n.Role
		}
	}
	personID, roleID := entityID(person), entityID(role)
	for _, want := range []struct{ id, uri, label string }{
		{personID, person, "anna"},
		{roleID, role, "qa-reviewer"},
	} {
		if byID[want.id] != "entity" {
			t.Errorf("%s: node type = %q, want \"entity\"", want.uri, byID[want.id])
		}
		if entityURI[want.id] != want.uri {
			t.Errorf("entity node must carry its full IRI: got %q, want %q", entityURI[want.id], want.uri)
		}
		if labels[want.id] != want.label {
			t.Errorf("entity label = %q, want %q", labels[want.id], want.label)
		}
	}

	var about, relation, fileAbout int
	for _, e := range g.Edges {
		switch {
		case e.Kind == "about" && e.To == personID:
			about++
		case e.Kind == "holds" && e.To == roleID:
			relation++
		case e.Kind == "about" && e.To == fileHash[:shortLen]:
			fileAbout++
		case e.To == entityID("pass"):
			t.Errorf("a literal object must not become an edge: %+v", e)
		}
	}
	if about != 1 {
		t.Errorf("claim about a URI subject should carry one about edge to it, got %d", about)
	}
	// the edge is labelled with the RELATION, not with the object's member key: what the claim
	// asserts is `holds`, and "id" would be a name for the encoding, not for the fact.
	if relation != 1 {
		t.Errorf("object IRI should be one edge labelled with the predicate, got %d", relation)
	}
	if fileAbout != 1 {
		t.Errorf("a content-hash subject must keep resolving to its hash node, got %d", fileAbout)
	}
}
