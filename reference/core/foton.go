package core

import "fmt"

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
		"protocol": f.Protocol,
	})
	if err != nil {
		return "", err
	}
	return HashBytes(b), nil
}

// EffectiveRef is the protocol ref used for IDENTITY (spec §6.2). When a descriptor is carried the
// ref is DERIVED from it - a stored ref is trusted only for a bare reference (no descriptor). This
// closes the cold-session cache-poisoning gap: a forged or stale `ref` beside a real descriptor can
// no longer decouple the action key from the actual protocol, because the action key recomputes the
// ref from the descriptor rather than believing the wire field.
func (p Protocol) EffectiveRef() (string, error) {
	if len(p.Descriptor) > 0 {
		return ComputeProtocolRef(p.Descriptor)
	}
	return p.Ref, nil
}

// CheckProtocolRef enforces the §6.2 binding at a trust boundary (ingest / reuse): if a descriptor
// is present, Protocol.Ref MUST equal sha256(canon(descriptor)). A mismatch is a malformed foton
// (its wire ref lies about its protocol) and is rejected rather than silently indexed.
func (f Foton) CheckProtocolRef() error {
	if len(f.Protocol.Descriptor) == 0 {
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
	if len(f.Protocol.Descriptor) == 0 {
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
