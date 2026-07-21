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
// semantics on top - a signed nekton attestation (gxp/tool-validation), not the kernel's verdict.

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"kton.dev/plankton/registry"
)

type spectrumMember struct {
	Name   string `json:"name"`
	Output string `json:"output"`          // reference output hash (sha256:...) - the gold result
	Model  string `json:"model,omitempty"` // optional provenance: the model input (hash or uri)
	Data   string `json:"data,omitempty"`  // optional provenance: the dataset input (hash or uri)
}

// spectrumDef is the on-disk manifest. Content-addressable like any file (`plankton hash`), so a
// spectrum can itself be pinned, mirrored, or registered as a foton later - it is just data that
// names other data by hash.
type spectrumDef struct {
	Spectrum   string           `json:"spectrum"`             // the tool identity, e.g. "nonmem"
	Of         string           `json:"of,omitempty"`         // human label, e.g. "the NONMEM 7.5 estimation tool"
	Normalizer string           `json:"normalizer,omitempty"` // the potential whose ray defines fulfilment (opaque id)
	Members    []spectrumMember `json:"members,omitempty"`    // the reference fotons (by output hash)
}

func spectrum(args []string) error {
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

// isContentHash reports whether s is a well-formed "sha256:<64 lowercase hex>" content hash. A member
// or candidate output that is empty/junk would otherwise be accepted, and `check`'s pure string
// equality would report a spectrum of empty members as "fulfilled" with nothing ever run.
func isContentHash(s string) bool {
	const p = "sha256:"
	if !strings.HasPrefix(s, p) || len(s) != len(p)+64 {
		return false
	}
	for _, c := range s[len(p):] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

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
	s, err := loadSpectrum(out)
	if err != nil {
		s = spectrumDef{}
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
		return fmt.Errorf("usage: plankton spectrum check <spectrum.json> --candidate name=sha256:outputHash ...")
	}
	s, err := loadSpectrum(args[0])
	if err != nil {
		return err
	}
	cand := map[string]string{}
	for i := 1; i < len(args); i++ {
		if args[i] == "--candidate" {
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
	// A memberless spectrum is vacuously fulfilled by anything (0/0), so `check` would exit 0 for any
	// or no candidate - a CI-gate footgun (cold-session finding). Refuse it: a tool defined by zero
	// reference fotons qualifies nothing.
	if len(s.Members) == 0 {
		return fmt.Errorf("spectrum %q defines no members; add reference fotons before checking (a memberless spectrum qualifies nothing, SPEC §10)", s.Spectrum)
	}
	// A --candidate naming something that is not a member is a typo the operator will misread as
	// coverage ("3/3") over a set they never actually checked. Refuse it rather than silently drop it.
	member := map[string]bool{}
	names := make([]string, len(s.Members))
	for i, m := range s.Members {
		member[m.Name] = true
		names[i] = m.Name
	}
	for name := range cand {
		if !member[name] {
			return fmt.Errorf("--candidate %q names no member of spectrum %q; members are: %s", name, s.Spectrum, strings.Join(names, ", "))
		}
	}
	r, err := registry.Open(dir())
	if err != nil {
		return err
	}
	fulfilled, missing := 0, 0
	for _, m := range s.Members {
		c, ok := cand[m.Name]
		if !ok {
			fmt.Printf("  %-24s no candidate given\n", m.Name)
			missing++
			continue
		}
		// The reference gold and the candidate must each be an OUTPUT of a real foton in this registry -
		// otherwise `fulfils`'s string-equality would score INVENTED hashes as "identical", so a
		// fabricated spectrum of hashes that back no computation "passes" against an empty store (while
		// `plankton show <hash>` correctly errors "no foton"). Not fulfilled if either does not resolve.
		if len(r.Producer(m.Output)) == 0 {
			fmt.Printf("  %-24s not fulfilled (reference is not a recorded foton output - fabricated member)\n", m.Name)
			continue
		}
		if len(r.Producer(c)) == 0 {
			fmt.Printf("  %-24s not fulfilled (candidate is not a recorded foton output - nothing was run)\n", m.Name)
			continue
		}
		switch fulfils(r, m.Output, c, s.Normalizer) {
		case "identical":
			fmt.Printf("  %-24s fulfilled (identical)\n", m.Name)
			fulfilled++
		case "via":
			fmt.Printf("  %-24s fulfilled (via potential %s in the ray)\n", m.Name, s.Normalizer)
			fulfilled++
		default:
			note := ""
			if s.Normalizer != "" {
				note = fmt.Sprintf("  (to converge via %s, an executor must apply it to both and `plankton add` the ray)", s.Normalizer)
			}
			fmt.Printf("  %-24s not fulfilled%s\n", m.Name, note)
		}
	}
	fmt.Printf("spectrum %q: %d/%d member(s) fulfilled (reproducible fact).\n", s.Spectrum, fulfilled, len(s.Members))
	fmt.Println("the \"validated at L0/L1\" judgment is semantics on top - record it in nekton (gxp/tool-validation).")
	// Distinct exit codes so a scripted gate can tell the three cases apart (not a verdict, a fact):
	//   0 = every member fulfilled; 1 = genuine FAILURE (a candidate was given but did not reproduce);
	//   2 = INCOMPLETE (a member had no candidate, so it was never checked). A failure outranks an
	// incompleteness, so exit 1 wins when both occur.
	switch {
	case fulfilled == len(s.Members):
		return nil
	case fulfilled+missing == len(s.Members): // no genuine failures, only unchecked members
		os.Exit(2)
	default:
		os.Exit(1)
	}
	return nil
}

// fulfils is plankton's reproducible ray comparison: "identical" if the raw terminals are equal,
// else "via" if they meet after following the same potential in the ray (both already produced by
// an executor and indexed), else "" (not fulfilled). Same rule as `plankton reproduces`; no L-level
// label and no verdict - those are semantics / an attestation, not the kernel's.
func fulfils(r *registry.Registry, ref, cand, potential string) string {
	if ref == cand {
		return "identical"
	}
	if potential != "" {
		if n := r.NormalizedOutput(ref, potential); n != "" && n == r.NormalizedOutput(cand, potential) {
			return "via"
		}
	}
	return ""
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
