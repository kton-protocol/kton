package foton_test

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"kton.dev/plankton/core"
	"kton.dev/plankton/foton"
	"kton.dev/plankton/registry"
	"kton.dev/plankton/spectrum"
)

// conditional is work() marked with the given conditions.
func conditional(cs ...core.Condition) foton.Spec {
	s := work("v1", "b.txt", "c.txt", "zusammen.R")
	p := *s.Protocol
	p.Conditions = cs
	s.Protocol = &p
	return s
}

func recordOf(t *testing.T, env core.Envelope) *core.Foton {
	t.Helper()
	st, err := env.Statement()
	if err != nil {
		t.Fatal(err)
	}
	f, err := st.ToFoton()
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func idAndKey(t *testing.T, spec foton.Spec) (string, string, core.Envelope) {
	t.Helper()
	env, id, err := foton.SignWith(spec, key("producer-a"))
	if err != nil {
		t.Fatal(err)
	}
	ak, err := recordOf(t, env).ActionKey()
	if err != nil {
		t.Fatal(err)
	}
	return id, ak, env
}

// The mark is covered: a conditional foton never shares an id or an action key with the unconditional
// computation, nor with the same step against another database. The order it is given in is not part
// of the work.
func TestConditional_OwnIdentityAndActionKey(t *testing.T) {
	plainID, plainAK, _ := idAndKey(t, work("v1", "b.txt", "c.txt", "zusammen.R"))
	prodID, prodAK, env := idAndKey(t, conditional(core.Condition{Kind: "network"}, core.Condition{Kind: "database", Ref: "prod"}))
	_, replicaAK, _ := idAndKey(t, conditional(core.Condition{Kind: "database", Ref: "replica"}, core.Condition{Kind: "network"}))
	sortedID, _, _ := idAndKey(t, conditional(core.Condition{Kind: "database", Ref: "prod"}, core.Condition{Kind: "network"}))

	if prodID == plainID || prodAK == plainAK {
		t.Error("a conditional foton shares an id or action key with the unconditional computation")
	}
	if prodAK == replicaAK {
		t.Error("the same step against prod and against a replica share an action key; ref must be covered")
	}
	if sortedID != prodID {
		t.Error("the order conditions are given in changed the id")
	}
	if f := recordOf(t, env); !f.Conditional() || f.Protocol.Conditions[0].Kind != "database" {
		t.Errorf("signed conditions not in canonical order or lost: %+v", f.Protocol.Conditions)
	}
	reg, err := registry.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mustAdd(t, reg, env)
}

func TestConditional_AuthoringRefuses(t *testing.T) {
	v0 := work("", "b.txt")
	p := *v0.Protocol
	p.Conditions = []core.Condition{{Kind: "database"}}
	v0.Protocol = &p
	for name, spec := range map[string]foton.Spec{
		"on v0":     v0,
		"empty":     conditional([]core.Condition{}...),
		"no kind":   conditional(core.Condition{Ref: "prod"}),
		"duplicate": conditional(core.Condition{Kind: "clock"}, core.Condition{Kind: "clock"}),
	} {
		if name == "empty" {
			pp := *spec.Protocol
			pp.Conditions = []core.Condition{}
			spec.Protocol = &pp
		}
		if _, _, err := foton.SignWith(spec, key("producer-a")); err == nil {
			t.Errorf("%s: a conditional spec that breaks the rules was signed", name)
		}
	}
}

// What a kernel that does not know the mark would merge, this one refuses: conditions on a v0
// statement, and every non-canonical spelling of them on v1.
func TestConditional_IngestRefuses(t *testing.T) {
	a := key("producer-a")
	good, err := foton.StatementPayload(conditional(core.Condition{Kind: "database", Ref: "prod"}, core.Condition{Kind: "network"}))
	if err != nil {
		t.Fatal(err)
	}
	mutate := func(fn func(proto map[string]any, st map[string]any)) []byte {
		var st map[string]any
		if err := json.Unmarshal(good, &st); err != nil {
			t.Fatal(err)
		}
		fn(st["predicate"].(map[string]any)["protocol"].(map[string]any), st)
		b, err := core.CanonValue(st)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for name, payload := range map[string][]byte{
		"on v0": mutate(func(_ map[string]any, st map[string]any) { st["predicateType"] = core.PredicateFoton }),
		"order": mutate(func(p map[string]any, _ map[string]any) {
			cs := p["conditions"].([]any)
			p["conditions"] = []any{cs[1], cs[0]}
		}),
		"empty": mutate(func(p map[string]any, _ map[string]any) { p["conditions"] = []any{} }),
		"duplicate": mutate(func(p map[string]any, _ map[string]any) {
			p["conditions"] = []any{p["conditions"].([]any)[1], p["conditions"].([]any)[1]}
		}),
		"no kind":        mutate(func(p map[string]any, _ map[string]any) { p["conditions"] = []any{map[string]any{"ref": "prod"}} }),
		"empty ref":      mutate(func(p map[string]any, _ map[string]any) { p["conditions"].([]any)[1].(map[string]any)["ref"] = "" }),
		"unknown member": mutate(func(p map[string]any, _ map[string]any) { p["conditions"].([]any)[1].(map[string]any)["ttl"] = "1h" }),
	} {
		reg, err := registry.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := reg.Add(signRaw(a, payload)); err == nil {
			t.Errorf("%s: admitted", name)
		}
	}
	reg, err := registry.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mustAdd(t, reg, signRaw(a, good))
}

// The faces that make a reproducibility statement do not let a conditional foton stand in for a
// computation: it does not count toward ↻N, a normalization through it is no normalization, a
// fulfilment cannot rest on it, and reuse and lineage say what it is.
func TestConditional_RegistryFaces(t *testing.T) {
	reg, err := registry.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db := core.Condition{Kind: "database", Ref: "prod"}
	out := h("ergebnis")
	// The same output, once computed and once captured from a database by another party.
	plain, _, err := foton.SignWith(work("v1", "b.txt"), key("producer-a"))
	if err != nil {
		t.Fatal(err)
	}
	mustAdd(t, reg, plain)
	captured, _, err := foton.SignWith(conditional(db), key("producer-c"))
	if err != nil {
		t.Fatal(err)
	}
	mustAdd(t, reg, captured)

	if rep := reg.Reproductions(out, nil); rep.DistinctSigners != 1 || rep.ExcludedConditional != 1 {
		t.Errorf("↻N counted a conditional producer: %+v", rep)
	}
	ak, _ := recordOf(t, captured).ActionKey()
	if hits := reg.ReuseHits(ak); len(hits) != 1 || len(hits[0].Conditions) != 1 || hits[0].Conditions[0] != db {
		t.Errorf("the reuse hit does not carry its conditions: %+v", hits)
	}

	// A normalizer that read the network: its "canonical form" is not followed.
	norm := foton.Spec{Statement: "v1", Inputs: []foton.FileSpec{{Path: "raw", Hash: out}},
		Outputs:  []foton.FileSpec{{Path: "canon", Hash: h("canonical")}},
		Protocol: &foton.ProtocolSpec{Kind: "normalize", Descriptor: map[string]any{"cmd": "fetch-schema && normalize"}, Conditions: []core.Condition{{Kind: "network"}}}}
	nenv, nid, err := foton.SignWith(norm, key("producer-a"))
	if err != nil {
		t.Fatal(err)
	}
	mustAdd(t, reg, nenv)
	if got := reg.NormalizedOutput(out, nid); got != "" {
		t.Errorf("a conditional normalizer was followed to %s", got)
	}
	if c := reg.ConditionalIn(reg.Lineage(h("canonical"))); len(c) != 2 {
		t.Errorf("lineage of the normalized output shows %d conditional fotons, want 2 (the normalizer and the capture)", len(c))
	}

	// A spectrum whose reference only a conditional foton produced is not fulfilled by matching it.
	onlyCaptured := h("snapshot")
	snap := conditional(db)
	snap.Outputs = []foton.FileSpec{{Path: "ergebnis.txt", Hash: onlyCaptured}}
	senv, _, err := foton.SignWith(snap, key("producer-c"))
	if err != nil {
		t.Fatal(err)
	}
	mustAdd(t, reg, senv)
	res, err := spectrum.Check(reg, spectrum.Spectrum{Spectrum: "tool", Members: []spectrum.Member{
		{Name: "computed", Output: out}, {Name: "captured", Output: onlyCaptured},
	}}, map[string]string{"computed": out, "captured": onlyCaptured})
	if err != nil {
		t.Fatal(err)
	}
	if res.Members[0].Status != spectrum.Identical || res.Members[1].Status != spectrum.ReferenceConditional {
		t.Errorf("spectrum statuses %+v; want identical, reference-conditional", res.Members)
	}
	if !strings.Contains(string(res.Outcome()), "failed") {
		t.Errorf("outcome %s; a fulfilment resting on a conditional foton must fail", res.Outcome())
	}
}

// Review C1: a potential marked conditional, applied by fotons that carry no mark (a v0 tool cannot),
// is not followed: the kernel can tell from the potential it is named by.
func TestConditional_PotentialNamedByIdIsNotFollowed(t *testing.T) {
	reg, err := registry.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	desc := map[string]any{"cmd": "convert-units --table https://units.example/convert"}
	pot := foton.Spec{Statement: "v1", Inputs: []foton.FileSpec{{Path: "raw"}}, Outputs: []foton.FileSpec{{Path: "canon"}},
		Protocol: &foton.ProtocolSpec{Kind: "normalize", Descriptor: desc, Conditions: []core.Condition{{Kind: "network", Ref: "https://units.example/convert"}}}}
	penv, pid, err := foton.SignWith(pot, key("producer-a"))
	if err != nil {
		t.Fatal(err)
	}
	mustAdd(t, reg, penv)
	rawA, rawB, canon := h("raw-a"), h("raw-b"), h("canon")
	for _, raw := range []string{rawA, rawB} {
		mustAdd(t, reg, mustSign(t, foton.Spec{Statement: "v1", Inputs: []foton.FileSpec{{Path: "raw", Hash: raw}},
			Outputs: []foton.FileSpec{{Path: "canon", Hash: canon}}, Protocol: &foton.ProtocolSpec{Kind: "normalize", Descriptor: desc}}))
		mustAdd(t, reg, mustSign(t, foton.Spec{Statement: "v1", Inputs: []foton.FileSpec{{Path: "in", Hash: h("in-" + raw)}},
			Outputs: []foton.FileSpec{{Path: "out", Hash: raw}}, Protocol: &foton.ProtocolSpec{Kind: "run", Descriptor: map[string]any{"cmd": raw}}}))
	}
	ref, err := core.ComputeProtocolRef(desc)
	if err != nil {
		t.Fatal(err)
	}
	// By foton id, and by its ref - the potential's primary name, which does not cover the conditions.
	for _, name := range []string{pid, ref} {
		if rep, err := reg.Reproduces(rawA, rawB, name); err != nil || rep.Matches {
			t.Errorf("reproduces --via a conditional potential named %s: %+v %v; want no match", name, rep, err)
		}
		if _, err := spectrum.Check(reg, spectrum.Spectrum{Spectrum: "tool", Normalizer: name,
			Members: []spectrum.Member{{Name: "m", Output: rawA}}}, map[string]string{"m": rawB}); err == nil {
			t.Errorf("a spectrum whose normalizer is a conditional potential named %s was checked", name)
		}
	}
	// Once the same potential is also recorded without conditions, its ref names an ordinary normalizer.
	plain := pot
	pp := *pot.Protocol
	pp.Conditions = nil
	plain.Protocol = &pp
	mustAdd(t, reg, mustSign(t, plain))
	if rep, err := reg.Reproduces(rawA, rawB, ref); err != nil || !rep.Matches {
		t.Errorf("the ref of a potential also recorded without conditions: %+v %v; want L1", rep, err)
	}
}

// Review C2: the count of independent producers and a spectrum fulfilment over a lineage that rests
// on a conditional step say so, like lineage does.
func TestConditional_UpstreamIsMarkedOnEveryReproducibilityAnswer(t *testing.T) {
	reg, err := registry.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	snap := conditional(core.Condition{Kind: "database", Ref: "prod"})
	snap.Outputs = []foton.FileSpec{{Path: "snap.csv", Hash: h("rows")}}
	mustAdd(t, reg, mustSign(t, snap))
	fit := foton.Spec{Statement: "v1", Inputs: []foton.FileSpec{{Path: "snap.csv", Hash: h("rows")}},
		Outputs: []foton.FileSpec{{Path: "fit.txt", Hash: h("fit")}}, Protocol: &foton.ProtocolSpec{Kind: "run", Descriptor: map[string]any{"cmd": "Rscript fit.R"}}}
	for _, k := range []string{"producer-a", "producer-c"} {
		env, _, err := foton.SignWith(fit, key(k))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := reg.Add(env); err != nil {
			t.Fatal(err)
		}
	}
	rep := reg.Reproductions(h("fit"), []ed25519.PublicKey{pub(key("producer-a")), pub(key("producer-c"))})
	if rep.DistinctSigners != 2 || len(rep.DependsOnConditional) != 1 {
		t.Errorf("reproductions: %d signers, %d conditional upstream; want 2 and 1", rep.DistinctSigners, len(rep.DependsOnConditional))
	}
	res, err := spectrum.Check(reg, spectrum.Spectrum{Spectrum: "tool", Members: []spectrum.Member{{Name: "m", Output: h("fit")}}},
		map[string]string{"m": h("fit")})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome() != spectrum.OutcomeFulfilled || len(res.DependsOnConditional) != 1 {
		t.Errorf("spectrum: outcome %s, %d conditional upstream; want fulfilled and 1", res.Outcome(), len(res.DependsOnConditional))
	}
}

func mustSign(t *testing.T, spec foton.Spec) core.Envelope {
	t.Helper()
	env, _, err := foton.SignWith(spec, key("producer-a"))
	if err != nil {
		t.Fatal(err)
	}
	return env
}
