package main

// spectrum.go promotes the spike's spectrum concept into the kernel. A SPECTRUM is the object
// that DEFINES A TOOL: the set of reference fotons (gold-standard model+data -> output) a tool
// must reproduce, plus the normaliser POTENTIAL whose ray defines the comparison. It starts life
// as a bare id and grows members.
//
// It is STRUCTURAL, not semantic - a set of hashes + a potential id - so it belongs in the
// protocol (unlike templates/ontology, which are federated data). `spectrum check` is REPRODUCIBLE
// REASONING: defined inputs (reference + candidate output fotons, the potential's ray) -> a defined
// output (is the spectrum fulfilled?), re-runnable to the same answer. Reproducible reasoning is a
// plankton concern. And true to the kernel invariant, it RUNS NOTHING: the candidate run and the
// normaliser application are executor jobs done elsewhere (a bash executor lives in testhelpers/,
// never the core package); plankton only compares the resulting fotons by hash.
//
// plankton reports *fulfilment* (does the candidate reproduce the reference set?). Whether that
// fulfilment is CALLED "L0" or "L1", and whether a human ACCEPTS it as a tool validation, is
// semantics on top - a signed nekton attestation under whatever term the reader's vocabulary
// uses for it, not the kernel's verdict.

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"kton.dev/plankton/registry"
	"kton.dev/plankton/spectrum"
)

// The manifest types and fulfilment live in kton.dev/plankton/spectrum, so a linking caller checks a
// spectrum with the same code this CLI runs.
type (
	spectrumMember = spectrum.Member
	spectrumDef    = spectrum.Spectrum
)

func spectrumCmd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: plankton spectrum <define|show|check> ...")
	}
	switch args[0] {
	case "define":
		return spectrumDefine(args[1:])
	case "show":
		return spectrumShow(args[1:])
	case "check":
		return spectrumCheck(args[1:])
	default:
		return fmt.Errorf("usage: plankton spectrum <define|show|check> ...")
	}
}

func loadSpectrum(path string) (spectrumDef, error) {
	var s spectrumDef
	b, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(b, &s)
}

func writeSpectrum(path string, s spectrumDef) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func isContentHash(s string) bool { return spectrum.IsContentHash(s) }

// spectrumDefine creates or extends a spectrum. It never executes; it only records references.
func spectrumDefine(args []string) error {
	var id, of, norm, out string
	var members []spectrumMember
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--id":
			i++
			id = arg(args, i)
		case "--of":
			i++
			of = arg(args, i)
		case "--normaliser", "--normalizer":
			i++
			norm = arg(args, i)
		case "--member":
			i++
			kv := arg(args, i)
			eq := strings.IndexByte(kv, '=')
			if eq < 0 {
				return fmt.Errorf("--member expects name=sha256:outputHash, got %q", kv)
			}
			if !isContentHash(kv[eq+1:]) {
				return fmt.Errorf("--member %q: output must be a sha256:<64hex> content hash, got %q", kv[:eq], kv[eq+1:])
			}
			members = append(members, spectrumMember{Name: kv[:eq], Output: kv[eq+1:]})
		case "-o":
			i++
			out = arg(args, i)
		default:
			return fmt.Errorf("unknown flag %q", args[i])
		}
	}
	if out == "" {
		if id == "" {
			return fmt.Errorf("usage: plankton spectrum define --id <id> [--of ..] [--normaliser P] [--member name=sha256:..] [-o file]")
		}
		out = id + ".spectrum.json"
	}
	// Extend an existing manifest if present, so a spectrum can start as a bare id and grow.
	//
	// ONLY a genuinely absent file starts a fresh one. Treating every read error as "nothing there"
	// meant a manifest that was malformed, unreadable or truncated got REPLACED by a fresh one on the
	// next `define` - a qualification corpus silently reduced to whatever this invocation named, with
	// a downstream check then run over fewer cases than the operator believed. A file we cannot read
	// is not a file that is not there.
	s, err := loadSpectrum(out)
	switch {
	case err == nil:
		// extend it
	case os.IsNotExist(err):
		s = spectrumDef{}
	default:
		return fmt.Errorf("refusing to overwrite %s: it exists but could not be read (%w).\n"+
			"  `define` extends a manifest, and extending one it cannot read would replace it with a\n"+
			"  fresh one holding only what this command named. Repair or move the file aside.", out, err)
	}
	if id != "" {
		s.Spectrum = id
	}
	if of != "" {
		s.Of = of
	}
	if norm != "" {
		s.Normalizer = norm
	}
	for _, m := range members {
		replaced := false
		for i := range s.Members {
			if s.Members[i].Name == m.Name {
				s.Members[i] = m
				replaced = true
				break
			}
		}
		if !replaced {
			s.Members = append(s.Members, m)
		}
	}
	if s.Spectrum == "" {
		return fmt.Errorf("a spectrum needs an --id")
	}
	// The spectrum JSON is a FILE (default <id>.spectrum.json), never stdout - so a well-meant
	// `spectrum define ... > my.spectrum.json` would otherwise capture the STATUS line, not the
	// spectrum (a silent footgun: the file then holds text that fails downstream as invalid JSON).
	// Two guards: `-o -` writes the spectrum itself to stdout; and the confirmation goes to STDERR,
	// so a stdout redirect captures the spectrum (with `-o -`) or nothing (loud), never the status.
	if out == "-" {
		b, err := json.MarshalIndent(s, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	if err := writeSpectrum(out, s); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "spectrum %q: %d member(s), normaliser=%s -> %s\n",
		s.Spectrum, len(s.Members), orNone(s.Normalizer), out)
	return nil
}

func spectrumShow(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: plankton spectrum show <spectrum.json>")
	}
	s, err := loadSpectrum(args[0])
	if err != nil {
		return err
	}
	fmt.Printf("spectrum: %s\n", s.Spectrum)
	if s.Of != "" {
		fmt.Printf("of:       %s\n", s.Of)
	}
	fmt.Printf("normaliser: %s   members: %d\n", orNone(s.Normalizer), len(s.Members))
	for _, m := range s.Members {
		fmt.Printf("  - %-24s output=%s\n", m.Name, m.Output)
	}
	return nil
}

// spectrumCheck reports whether a candidate tool FULFILS the spectrum: per member, does the
// candidate output reproduce the reference output - identically, or after following the normaliser
// potential in the ray? plankton compares fotons that already exist (the candidate run and the
// normaliser application are executor jobs done elsewhere and `add`ed); it runs nothing. It renders
// NO graded verdict: "fulfilled" is a reproducible fact; calling it L0/L1 and ACCEPTING it as a
// tool validation is a nekton attestation on top.
func spectrumCheck(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: plankton spectrum check <spectrum.json> --candidate name=sha256:outputHash ... [--json]")
	}
	s, err := loadSpectrum(args[0])
	if err != nil {
		return err
	}
	cand := map[string]string{}
	asJSON := false
	for i := 1; i < len(args); i++ {
		if args[i] == "--json" {
			asJSON = true
		} else if args[i] == "--candidate" {
			i++
			kv := arg(args, i)
			eq := strings.IndexByte(kv, '=')
			if eq < 0 {
				return fmt.Errorf("--candidate expects name=sha256:outputHash, got %q", kv)
			}
			if !isContentHash(kv[eq+1:]) {
				return fmt.Errorf("--candidate %q: output must be a sha256:<64hex> content hash, got %q", kv[:eq], kv[eq+1:])
			}
			cand[kv[:eq]] = kv[eq+1:]
		} else {
			return fmt.Errorf("unknown arg %q", args[i])
		}
	}
	r, err := registry.Open(dir())
	if err != nil {
		return err
	}
	res, err := spectrum.Check(r, s, cand)
	if err != nil {
		return err
	}
	if asJSON {
		// The same answer as the prose, per member and as an outcome; the exit code does not change.
		if err := printJSON(struct {
			spectrum.Result
			Outcome spectrum.Outcome `json:"outcome"`
		}{res, res.Outcome()}); err != nil {
			return err
		}
		return exitFor(res.Outcome())
	}
	for _, m := range res.Members {
		switch m.Status {
		case spectrum.NoCandidate:
			fmt.Printf("  %-24s no candidate given\n", m.Name)
		case spectrum.ReferenceNotRecorded:
			fmt.Printf("  %-24s not fulfilled (reference is not a recorded foton output - fabricated member)\n", m.Name)
		case spectrum.CandidateNotRecorded:
			fmt.Printf("  %-24s not fulfilled (candidate is not a recorded foton output - nothing was run)\n", m.Name)
		case spectrum.ReferenceConditional:
			fmt.Printf("  %-24s not fulfilled (every producer of the reference is a conditional foton - a fulfilment cannot rest on one)\n", m.Name)
		case spectrum.CandidateConditional:
			fmt.Printf("  %-24s not fulfilled (every producer of the candidate is a conditional foton - a fulfilment cannot rest on one)\n", m.Name)
		case spectrum.Identical:
			fmt.Printf("  %-24s fulfilled (identical)\n", m.Name)
		case spectrum.Via:
			fmt.Printf("  %-24s fulfilled (via potential %s in the ray)\n", m.Name, res.Normalizer)
		default:
			note := ""
			if s.Normalizer != "" {
				note = fmt.Sprintf("  (to converge via %s, an executor must apply it to both and `plankton add` the ray)", res.Normalizer)
			}
			fmt.Printf("  %-24s not fulfilled%s\n", m.Name, note)
		}
	}
	fmt.Printf("spectrum %q: %d/%d member(s) fulfilled (reproducible fact).\n", s.Spectrum, res.Fulfilled, len(s.Members))
	if n := len(res.DependsOnConditional); n > 0 {
		fmt.Printf("note: the compared outputs depend on %d conditional foton(s) upstream - reproducible only as far as their conditions held (SPEC §11)\n", n)
	}
	// Names no template. Which term carries that judgment is APPLICATION vocabulary (SPEC §7.1: the
	// kernel treats every predicate as an opaque IRI), it lives in whatever alias set the reader
	// uses, and it is not the kernel's to pick - naming one here made a plankton command depend on
	// what a template in another repository happened to be called.
	fmt.Println("the \"validated at L0/L1\" judgment is semantics on top - record it as a claim in nekton.")
	// Distinct exit codes so a scripted gate can tell the three cases apart (not a verdict, a fact):
	//   0 = every member fulfilled; 1 = genuine FAILURE (a candidate was given but did not reproduce);
	//   2 = INCOMPLETE (a member had no candidate, so it was never checked). A failure outranks an
	// incompleteness, so exit 1 wins when both occur.
	return exitFor(res.Outcome())
}

func exitFor(o spectrum.Outcome) error {
	switch o {
	case spectrum.OutcomeFulfilled:
		return nil
	case spectrum.OutcomeIncomplete:
		os.Exit(2)
	default:
		os.Exit(1)
	}
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func arg(args []string, i int) string {
	if i < len(args) {
		return args[i]
	}
	return ""
}
