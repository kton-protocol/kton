package foton_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"kton.dev/plankton/core"
	"kton.dev/plankton/foton"
	"kton.dev/plankton/registry"
)

func key(label string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte(label))
	return ed25519.NewKeyFromSeed(s[:])
}

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

func h(c string) string {
	s := sha256.Sum256([]byte(c))
	return "sha256:" + strings.ToLower(strings.TrimSpace(base16(s[:])))
}

func base16(b []byte) string {
	const hx = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hx[c>>4], hx[c&15])
	}
	return string(out)
}

// work is one computation, its inputs listed in the order given.
func work(stmt string, order ...string) foton.Spec {
	files := map[string]string{"zusammen.R": "script", "b.txt": "B", "c.txt": "C"}
	var ins []foton.FileSpec
	for _, p := range order {
		ins = append(ins, foton.FileSpec{Path: p, Hash: h(files[p])})
	}
	return foton.Spec{Statement: stmt, Inputs: ins,
		Outputs:  []foton.FileSpec{{Path: "ergebnis.txt", Hash: h("ergebnis")}},
		Protocol: &foton.ProtocolSpec{Kind: "script", Descriptor: map[string]any{"cmd": "Rscript zusammen.R"}}}
}

// K7. Inputs are keyed by path (SPEC §6.2), so their order is not part of the work. In v0 it is
// part of the id; in v1 it is not.
func TestV1_InputOrderDoesNotChangeTheId(t *testing.T) {
	a, _ := foton.FotonID(work("v0", "zusammen.R", "b.txt", "c.txt"))
	b, _ := foton.FotonID(work("v0", "b.txt", "c.txt", "zusammen.R"))
	if a == b {
		t.Fatal("precondition: v0 ids are order-sensitive (if this changed, K7 is moot)")
	}
	c, _ := foton.FotonID(work("v1", "zusammen.R", "b.txt", "c.txt"))
	d, _ := foton.FotonID(work("v1", "b.txt", "c.txt", "zusammen.R"))
	if c != d {
		t.Fatalf("v1: the same work in two input orders has two ids: %s %s", c, d)
	}
	pc, _ := foton.StatementPayload(work("v1", "zusammen.R", "b.txt", "c.txt"))
	pd, _ := foton.StatementPayload(work("v1", "c.txt", "zusammen.R", "b.txt"))
	if string(pc) != string(pd) {
		t.Fatal("v1: the same work must be the same signed bytes")
	}
}

// v1 has its own id space: the same work recorded as v0 and as v1 are two records. Were they one,
// a v0 twin already in a registry would hold the id with a different payload, and every v1
// co-signature would be turned away exactly as before.
func TestV1_IsNeverTheSameRecordAsV0(t *testing.T) {
	v0, _ := foton.FotonID(work("v0", "b.txt", "c.txt", "zusammen.R"))
	v1, _ := foton.FotonID(work("v1", "b.txt", "c.txt", "zusammen.R"))
	if v0 == v1 {
		t.Fatalf("v0 and v1 share the id %s", v0)
	}
}

// K5. Two producers of the same work, each wanting to say where THEIR copies live. In v0 the uri is
// in the signed bytes, so the registry keeps the first record and drops the second signature. In v1
// both sign the same bytes; the signatures union; the locators travel as material, one per producer.
func TestV1_TwoProducersCoSignAndKeepTheirOwnLocators(t *testing.T) {
	autorin, user := key("autorin"), key("user")
	dir := t.TempDir()
	reg, err := registry.Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	// v0 first, as the motivation: the second signature is lost.
	v0a, v0b := work("v0", "b.txt", "c.txt", "zusammen.R"), work("v0", "b.txt", "c.txt", "zusammen.R")
	v0a.Outputs[0].URI = []string{"https://autorin.example/ergebnis.txt"}
	v0b.Outputs[0].URI = []string{"https://user.example/ergebnis.txt"}
	ea, id0, _ := foton.SignWith(v0a, autorin)
	eb, _, _ := foton.SignWith(v0b, user)
	mustAdd(t, reg, ea)
	mustAdd(t, reg, eb)
	if env, _ := reg.Envelope(id0); len(env.Signatures) != 1 { // v0 stays as it was
		t.Fatalf("precondition: v0 keeps one signature across differing payloads, got %d", len(env.Signatures))
	}

	// v1: the same bytes, both signatures.
	ea1, id1, err := foton.SignWith(work("v1", "zusammen.R", "b.txt", "c.txt"), autorin)
	if err != nil {
		t.Fatal(err)
	}
	eb1, idb, _ := foton.SignWith(work("v1", "c.txt", "b.txt", "zusammen.R"), user)
	if idb != id1 {
		t.Fatalf("v1 ids differ: %s %s", id1, idb)
	}
	mustAdd(t, reg, ea1)
	mustAdd(t, reg, eb1)
	env, _ := reg.Envelope(id1)
	for name, k := range map[string]ed25519.PrivateKey{"autorin": autorin, "user": user} {
		if core.VerifiedSignerKeyID(env, []ed25519.PublicKey{pub(k)}) == "" {
			t.Errorf("the v1 record carries no valid signature of %s", name)
		}
	}

	// Each producer's locators, as material beside the record.
	out := []foton.FileSpec{{Path: "ergebnis.txt", Hash: h("ergebnis")}}
	for who, k := range map[string]ed25519.PrivateKey{"autorin": autorin, "user": user} {
		out[0].URI = []string{"https://" + who + ".example/ergebnis.txt"}
		m, err := foton.SignLocators(id1, out, k)
		if err != nil {
			t.Fatal(err)
		}
		if err := reg.AttachMaterial(registry.VerificationMaterial{Subject: m.Subject, Scheme: m.Scheme,
			MediaType: m.MediaType, Material: m.Material}); err != nil {
			t.Fatal(err)
		}
	}
	reg, _ = registry.Open(dir) // read back from disk
	f, _ := reg.Foton(id1)
	got := map[string]string{}
	for _, m := range reg.Material(id1) {
		ls, err := foton.ReadLocators(m.Scheme, m.Material, *f, []ed25519.PublicKey{pub(autorin), pub(user)})
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range ls {
			got[l.Signer] = l.URI[0]
		}
	}
	if got[core.KeyIDHex(pub(autorin))] != "https://autorin.example/ergebnis.txt" ||
		got[core.KeyIDHex(pub(user))] != "https://user.example/ergebnis.txt" {
		t.Fatalf("each producer keeps its own locators: %v", got)
	}
}

func mustAdd(t *testing.T, reg *registry.Registry, env core.Envelope) {
	t.Helper()
	if _, _, err := reg.Add(env); err != nil {
		t.Fatal(err)
	}
}

// A v1 record that varies what v1 fixes is refused at ingest - signed elsewhere and arriving by
// mirror or merge, it would otherwise reopen the byte-different twins v1 exists to end.
func TestV1_IngestRefusesANonCanonicalV1Record(t *testing.T) {
	k := key("x")
	good, _ := foton.StatementPayload(work("v1", "b.txt", "c.txt", "zusammen.R"))
	var st map[string]any
	_ = json.Unmarshal(good, &st)
	pred := st["predicate"].(map[string]any)
	ins := pred["inputs"].([]any)

	cases := map[string]func(){
		"unsorted inputs": func() { ins[0], ins[1] = ins[1], ins[0] },
		"uri on a subject": func() {
			st["subject"].([]any)[0].(map[string]any)["uri"] = []any{"https://x.example/e"}
		},
		"specVersion": func() { pred["specVersion"] = "0.1" },
	}
	for name, mutate := range cases {
		_ = json.Unmarshal(good, &st)
		pred = st["predicate"].(map[string]any)
		ins = pred["inputs"].([]any)
		mutate()
		payload, err := core.CanonValue(st)
		if err != nil {
			t.Fatal(err)
		}
		env := core.Envelope{PayloadType: core.PayloadType, Payload: base64.StdEncoding.EncodeToString(payload)}
		env.Signatures = append(env.Signatures, struct {
			KeyID string `json:"keyid"`
			Sig   string `json:"sig"`
		}{core.KeyIDHex(pub(k)), base64.StdEncoding.EncodeToString(ed25519.Sign(k, core.PAE(core.PayloadType, payload)))})
		reg, _ := registry.Open(t.TempDir())
		if _, _, err := reg.Add(env); err == nil {
			t.Errorf("%s: a non-canonical v1 record was admitted", name)
		}
	}
}

// Authoring refuses a v1 spec with a uri instead of signing it away.
func TestV1_AuthoringRefusesAUri(t *testing.T) {
	s := work("v1", "b.txt", "c.txt", "zusammen.R")
	s.Outputs[0].URI = []string{"https://x.example/e"}
	if _, _, err := foton.SignWith(s, key("x")); err == nil || !strings.Contains(err.Error(), "SignLocators") {
		t.Fatalf("want a refusal naming SignLocators, got %v", err)
	}
}

// A locator is about THIS record's files: naming bytes the foton does not contain is refused, and
// a locator signed by a key the reader does not hold is not read.
func TestLocators_OnlyThisRecordsFilesAndOnlyGivenKeys(t *testing.T) {
	k, other := key("k"), key("other")
	spec := work("v1", "b.txt", "c.txt", "zusammen.R")
	_, id, _ := foton.SignWith(spec, k)
	f := core.Foton{Statement: "v1", Protocol: core.Protocol{Kind: "script", Descriptor: spec.Protocol.Descriptor}}
	f.Protocol.Ref, _ = core.ComputeProtocolRef(spec.Protocol.Descriptor)
	for _, in := range spec.Inputs {
		f.Inputs = append(f.Inputs, core.FileRef{Path: in.Path, Hash: in.Hash})
	}
	f.Outputs = []core.FileRef{{Path: "ergebnis.txt", Hash: h("ergebnis")}}
	core.SortRefs(f.Inputs)

	foreign, _ := foton.SignLocators(id, []foton.FileSpec{{Path: "ergebnis.txt", Hash: h("anders"), URI: []string{"https://x.example"}}}, k)
	if _, err := foton.ReadLocators(foreign.Scheme, foreign.Material, f, []ed25519.PublicKey{pub(k)}); err == nil {
		t.Error("a locator for bytes the foton does not contain was read")
	}
	ok, _ := foton.SignLocators(id, []foton.FileSpec{{Path: "ergebnis.txt", Hash: h("ergebnis"), URI: []string{"https://x.example"}}}, k)
	if _, err := foton.ReadLocators(ok.Scheme, ok.Material, f, []ed25519.PublicKey{pub(other)}); err == nil {
		t.Error("a locator signed by a key the reader does not hold was read")
	}
	if ls, err := foton.ReadLocators(ok.Scheme, ok.Material, f, []ed25519.PublicKey{pub(k)}); err != nil || len(ls) != 1 {
		t.Errorf("a valid locator: %v %v", ls, err)
	}
	if ls, err := foton.ReadLocators("rekor", ok.Material, f, nil); ls != nil || err != nil {
		t.Error("material of another scheme is simply not a locator")
	}
}
