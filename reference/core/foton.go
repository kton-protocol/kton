package core

import (
	"fmt"
	"path/filepath"
	"strings"
)

// FileRef references a file by content hash; located by uri; optionally identified by id.
// Path is the file's RELATIVE path within the foton's work tree (e.g. "raw/data.csv",
// "modelfit_dir1/NM_run1/run.lst"). Relative paths are structural - tools depend on layout -
// so they are part of the foton's identity and action key. Absolute paths / sandbox roots
// are incidental and are never recorded. plankton stores no bytes (spec §6.1).
//
// An ABSENT Hash marks an UNBOUND slot, identified by Path: an input HOLE or a virtual
// OUTPUT. A foton with unbound slots is a POTENTIAL (a template/normalizer); an executor
// realizes it by binding the holes to input hashes and producing the (virtual) outputs,
// keeping only the declared virtual outputs. The kernel does not interpret unbound slots -
// it canonicalizes/stores them by Path; FotonID stays stable for a potential, distinct from
// any realization. (Bound FileRefs are unaffected: a non-empty Hash always canonicalizes.)
type FileRef struct {
	Hash      string   `json:"hash,omitempty"`
	Path      string   `json:"path,omitempty"`
	ID        string   `json:"id,omitempty"`
	URI       []string `json:"uri,omitempty"`
	MediaType string   `json:"mediaType,omitempty"`
}

// Protocol is the opaque, content-addressed transformation descriptor (spec §6.2). Its
// descriptor SHOULD include output-capture patterns (which relative paths/globs are the
// foton's outputs) so tool-created scratch subfolders are excluded.
type Protocol struct {
	Kind       string         `json:"kind"`
	Ref        string         `json:"ref"`
	Descriptor map[string]any `json:"descriptor,omitempty"`
}

// Foton is a transformation edge: an input tree -> protocol -> an output tree (spec §6.2).
// Inputs and outputs are keyed by relative path.
type Foton struct {
	Inputs   []FileRef `json:"inputs"`
	Outputs  []FileRef `json:"outputs"`
	Protocol Protocol  `json:"protocol"`
}

// coveredRefs projects FileRefs to their COVERED fields only - hash and the structural relative
// path. `id`, `uri`, and `mediaType` are CARRIED, not covered (spec §6.1): they locate/describe a
// file but MUST NOT affect identity, so adding a location hint never changes a foton's id.
func coveredRefs(refs []FileRef) []any {
	out := make([]any, 0, len(refs))
	for _, r := range refs {
		m := map[string]any{}
		if r.Hash != "" {
			m["hash"] = r.Hash
		}
		if r.Path != "" {
			m["path"] = r.Path
		}
		out = append(out, m)
	}
	return out
}

// FotonID is the content address of the foton over its COVERED fields (spec §6.3): the covered
// projection excludes carried FileRef fields (id/uri/mediaType), so a foton's identity depends only
// on its input/output hashes+paths and its protocol - not on where the files happen to be located.
func (f Foton) FotonID() (string, error) {
	b, err := CanonValue(map[string]any{
		"inputs":   coveredRefs(f.Inputs),
		"outputs":  coveredRefs(f.Outputs),
		"protocol": f.coveredProtocol(),
	})
	if err != nil {
		return "", err
	}
	return HashBytes(b), nil
}

// coveredProtocol is the protocol as IDENTITY sees it. It exists so identity and the action key
// agree about one thing: whether a descriptor is PRESENT.
//
// Marshalling Protocol through its struct tags used `descriptor,omitempty`, and for a map omitempty
// drops an EMPTY map as well as a nil one - so `descriptor: {}` and no descriptor at all produced
// the same covered bytes and the same foton id. EffectiveRef and ActionKey draw the opposite
// distinction, and deliberately: only nil is absent there, because a bare ref is an unverifiable
// pointer to an off-record protocol and must not share an action key with an inline descriptor.
//
// Identical id, different action key: the `{}` form was taken for a duplicate of the descriptor-less
// one on ingest and never acquired its own entry in the reuse index. One record, two answers about
// what it is.
//
// Presence is therefore explicit here. Non-empty and nil descriptors produce exactly the bytes they
// produced before - the key set is unchanged and CanonValue sorts - so no existing foton id moves;
// only `{}`, which no record in this repository or in the example suite carries, becomes distinct.
func (f Foton) coveredProtocol() map[string]any {
	p := map[string]any{"kind": f.Protocol.Kind, "ref": f.Protocol.Ref}
	if f.Protocol.Descriptor != nil {
		p["descriptor"] = f.Protocol.Descriptor
	}
	return p
}

// ValidateStructure enforces the CONTEXT-FREE structure of a foton: the parts that can be decided
// from the record alone, with no registry and no other record in hand.
//
// It lives here, beside the type, so that authoring, `verify`, ingest and the read path apply one
// definition. They used not to: authoring refused a malformed hash and an escaping path, ingest
// checked only the protocol binding and the action key, and the read path matched ingest - so a
// foton with input digest `sha256:not-a-digest` or path `/outside.csv`, signed elsewhere and
// arriving by mirror or by a git merge, was accepted and indexed. Every boundary that admits a
// record has to agree on what a record is.
//
// This is PLANKTON's structure and nothing else's. nekton's context-free rules are its own
// (claim.ValidateChainStructure: where genesis may appear, that a seed carries no prev) and the two
// share nothing but the envelope layer above them - a foton has no prev, a claim has no inputs.
func (f Foton) ValidateStructure() error {
	if err := validateRefStructure("input", f.Inputs, true); err != nil {
		return err
	}
	return validateRefStructure("output", f.Outputs, false)
}

// validateRefStructure checks one slot list. dedupePaths is true for inputs only: the §6.3 action key
// is a {relpath -> hash} map, so two inputs at one path cannot both be in the computation's identity
// - a silent last-wins would erase an input and let a 2-input foton falsely reuse a 1-input result.
// Outputs are not in the action key, so they carry no such ambiguity.
func validateRefStructure(kind string, refs []FileRef, dedupePaths bool) error {
	seen := map[string]string{}
	for i, r := range refs {
		// A BOUND slot must carry a hash this substrate can resolve (§5.1).
		if r.Hash != "" {
			if _, ok := NormalizeContentHash(r.Hash); !ok {
				return fmt.Errorf("%s[%d] %q: %q is not a sha256 content hash (SPEC §5.1)", kind, i, r.Path, r.Hash)
			}
		}
		// A path is a location INSIDE the work tree and is structural - it goes into the action key.
		// An absolute path, or one that escapes upward, describes a different machine's filesystem
		// rather than a reproducible computation (SPEC §6.1).
		if r.Path != "" {
			if filepath.IsAbs(r.Path) || strings.HasPrefix(r.Path, "/") || strings.HasPrefix(r.Path, `\`) {
				return fmt.Errorf("%s[%d] path %q is absolute; a foton's paths are relative to the "+
					"work tree (SPEC §6.1)", kind, i, r.Path)
			}
			if p := filepath.ToSlash(filepath.Clean(r.Path)); p == ".." || strings.HasPrefix(p, "../") {
				return fmt.Errorf("%s[%d] path %q escapes the work tree (SPEC §6.1)", kind, i, r.Path)
			}
		}
		if !dedupePaths || r.Path == "" {
			continue
		}
		key := filepath.ToSlash(filepath.Clean(r.Path))
		if prev, dup := seen[key]; dup && prev != r.Hash {
			return fmt.Errorf("two inputs share path %q with different hashes (%s, %s) - the action "+
				"key is a {path -> hash} map and could hold only one, so an input would silently "+
				"vanish from the computation's identity (SPEC §6.3)", r.Path, prev, r.Hash)
		}
		seen[key] = r.Hash
	}
	return nil
}

// EffectiveRef is the protocol ref used for IDENTITY (spec §6.2). When a descriptor is carried the
// ref is DERIVED from it - a stored ref is trusted only for a bare reference (no descriptor). This
// closes the cold-session cache-poisoning gap: a forged or stale `ref` beside a real descriptor can
// no longer decouple the action key from the actual protocol, because the action key recomputes the
// ref from the descriptor rather than believing the wire field.
func (p Protocol) EffectiveRef() (string, error) {
	// PRESENT, including empty: `descriptor: {}` is a descriptor and is hashed. `len(...) > 0`
	// treated it as absent, which both skipped the §6.2 check and put the ref in the
	// bare/unverifiable action-key namespace. Only nil is absent.
	if p.Descriptor != nil {
		return ComputeProtocolRef(p.Descriptor)
	}
	return p.Ref, nil
}

// CheckProtocolRef enforces the §6.2 binding at a trust boundary (ingest / reuse): if a descriptor
// is present, Protocol.Ref MUST equal sha256(canon(descriptor)). A mismatch is a malformed foton
// (its wire ref lies about its protocol) and is rejected rather than silently indexed.
func (f Foton) CheckProtocolRef() error {
	// A PRESENT descriptor is hashed, even when it is empty. `len(...) == 0` conflated
	// `descriptor: {}` with no descriptor at all, so an empty object let an arbitrary incorrect ref
	// through unchecked. §6.2 requires hashing any descriptor that is there, and
	// `{}` canonicalizes and hashes perfectly well; only ABSENT means unverifiable.
	if f.Protocol.Descriptor == nil {
		return nil
	}
	want, err := ComputeProtocolRef(f.Protocol.Descriptor)
	if err != nil {
		return err
	}
	if f.Protocol.Ref != want {
		return fmt.Errorf("protocol.ref %s does not match sha256(canon(descriptor)) %s (SPEC §6.2)", f.Protocol.Ref, want)
	}
	return nil
}

// ActionKey is the reuse/cache key: sha256(canonicalJSON({inputs:{relpath->hash},
// protocol:{kind,ref}})) (spec §6.3). Relative input paths are included (structural);
// absolute roots are not. Outputs are not in the key - they are what you compute. The ref is the
// EFFECTIVE ref (derived from the descriptor when present), so the cache key reflects the real
// protocol, not an unverified wire field.
func (f Foton) ActionKey() (string, error) {
	tree := map[string]any{}
	for _, in := range f.Inputs {
		key := in.Path
		if key == "" {
			key = in.Hash // fall back to hash if no path given
		}
		// Two inputs at the same relative path are ambiguous: the {relpath->hash} map can hold only
		// one, so a silent last-wins would erase an input from the computation identity and let a
		// 2-input foton falsely reuse a 1-input result (cold-session finding). Reject the ambiguity.
		if prev, dup := tree[key]; dup && prev != in.Hash {
			return "", fmt.Errorf("two inputs share relpath %q with different hashes (%v, %s) - ambiguous computation identity", key, prev, in.Hash)
		}
		tree[key] = in.Hash
	}
	ref, err := f.Protocol.EffectiveRef()
	if err != nil {
		return "", err
	}
	proto := map[string]any{"kind": f.Protocol.Kind, "ref": ref}
	if f.Protocol.Descriptor == nil {
		// A bare ref (no carried descriptor) is an UNVERIFIABLE pointer to an off-record protocol.
		// Namespace it so it can never share an action key with a VERIFIABLE inline descriptor whose
		// content happens to hash to the same ref - the cold-session bypass where an attacker's
		// descriptor-less foton asserts ref = sha256(canon(victim's descriptor)) and poisons the
		// victim's cache. A descriptor-ful action key is unchanged (this branch does not run).
		proto["refUnverified"] = true
	}
	m := map[string]any{"inputs": tree, "protocol": proto}
	b, err := CanonValue(m)
	if err != nil {
		return "", err
	}
	return HashBytes(b), nil
}

// ComputeProtocolRef returns the content address of a protocol descriptor; it MUST equal
// Protocol.Ref when the descriptor is present (spec §6.2).
func ComputeProtocolRef(descriptor map[string]any) (string, error) {
	b, err := CanonValue(descriptor)
	if err != nil {
		return "", err
	}
	return HashBytes(b), nil
}
