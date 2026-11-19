package registry

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"kton.dev/nekton/claim"
	"kton.dev/plankton/core"
)

// The write path into a store with the caller's own key (#213). This is the same behaviour as the
// CLI's `--add`, offered to linked writers (the cockpit's say) so they place claims identically:
// a claim that names no scope chains under the store's root, a seed without a parent hangs off the
// root and is registered in it, and a store without a root gets one, signed by the caller.
//
// Signing here is the signing helper SPEC §8 permits for a caller that holds its own key. It is never
// reached from Add, mirror or sync: a kernel does not sign on ingest.

// rootName is the scope name of a store's root seed: "root/" and a random part, so two stores'
// roots never share an id - by and when alone collided for one key within one second (#259 review
// R2). A caller that needs a reproducible root (a corpus rebuilt to the same ids) names it.
func rootName() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	return "root/" + hex.EncodeToString(b)
}

func defaultBy(priv ed25519.PrivateKey) string {
	sum := sha256.Sum256(priv.Public().(ed25519.PublicKey))
	return "key:" + hex.EncodeToString(sum[:])[:16]
}

// now is the timestamp of entries the store writes itself (a root seed without --when, a registration).
// A variable so a test can pin it.
var now = func() string { return time.Now().UTC().Format(time.RFC3339) }

// CreateRoot signs a root seed with priv, stores it and records it as this store's root. by defaults
// to key:<keyid>, when to now, name to "root/<random>".
func (r *Registry) CreateRoot(priv ed25519.PrivateKey, by, when, name string) (string, error) {
	if r.root.Root != "" {
		return "", fmt.Errorf("this store already has a root: %s", r.root.Root)
	}
	if by == "" {
		by = defaultBy(priv)
	}
	if when == "" {
		when = now()
	}
	if name == "" {
		name = rootName()
	}
	env, id, err := claim.SignWith(claim.Spec{
		Subject:       []claim.SubjectSpec{{URI: "urn:nekton:scope:" + name}},
		PredicateType: claim.ScopePredicateType,
		PredicateBody: map[string]any{"scope": name, "genesis": true, "by": by, "when": when},
	}, priv)
	if err != nil {
		return "", err
	}
	if _, _, err := r.Add(env); err != nil {
		return "", err
	}
	if err := r.SetRoot(id, ""); err != nil {
		return "", err
	}
	return id, nil
}

// Place prepares spec for writing into this store: a claim that names no scope gets scope = the root
// and prev = the root head; a seed without a parent gets parent = the root. A store without a root
// gets one first, signed with priv; createdRoot is its id then, "" otherwise. A spec that names a
// scope, or a seed that names a parent, is left as the caller wrote it.
func (r *Registry) Place(spec *claim.Spec, priv ed25519.PrivateKey) (createdRoot string, err error) {
	seed := spec.PredicateType == claim.ScopePredicateType
	if seed {
		if _, has := spec.PredicateBody["parent"]; has {
			return "", nil
		}
	} else if spec.Scope != "" || spec.PredicateBody["scope"] != nil {
		return "", nil
	}
	if r.root.Root == "" {
		by, _ := spec.PredicateBody["by"].(string)
		if by == "" {
			by = spec.By
		}
		if createdRoot, err = r.CreateRoot(priv, by, "", ""); err != nil {
			return "", fmt.Errorf("this store has no root yet and creating one failed: %w", err)
		}
	}
	switch {
	case seed:
		spec.PredicateBody["parent"] = map[string]any{"hash": r.root.Root}
	case spec.PredicateBody != nil:
		spec.PredicateBody["scope"] = r.root.Root
		spec.PredicateBody["prev"] = r.RootHead()
	default:
		spec.Scope, spec.Prev = r.root.Root, r.RootHead()
	}
	return createdRoot, nil
}

// RegisterSubnekton appends the root entry that registers a seed this store opened (nk:registers).
// when is the seed's own time, so a corpus written with fixed times rebuilds to the same root chain;
// "" means now, as for CreateRoot.
func (r *Registry) RegisterSubnekton(seedID string, priv ed25519.PrivateKey, by, when string) (string, error) {
	if r.root.Root == "" {
		return "", fmt.Errorf("this store has no root to register %s in", seedID)
	}
	if by == "" {
		by = defaultBy(priv)
	}
	if when == "" {
		when = now()
	}
	env, id, err := claim.SignWith(claim.Spec{
		Subject:   []claim.SubjectSpec{{Hash: seedID}},
		Predicate: RegistersPredicate,
		By:        by,
		When:      when,
		Scope:     r.root.Root,
		Prev:      r.RootHead(),
	}, priv)
	if err != nil {
		return "", err
	}
	if _, _, err := r.Add(env); err != nil {
		return "", err
	}
	r.ownAppend(id) // this store's own entry: the head moves (#259 review R1)
	return id, nil
}

// Written is what Write did.
type Written struct {
	ID          string        // the claim (or seed) id
	Envelope    core.Envelope // what was signed and stored
	IsNew       bool          // false: the store already held it (a twin)
	CreatedRoot string        // the root created for this write, if any
	Registered  string        // the root entry registering a new seed, if any
}

// Write places spec in this store (Place), signs it with priv, stores it, and registers a new seed in
// the root: the whole `--add` write path in one call.
func (r *Registry) Write(spec claim.Spec, priv ed25519.PrivateKey) (Written, error) {
	var w Written
	var err error
	// A write registry loads every scope file this write touches BEFORE anything is stored: the root
	// (an unscoped claim chains there, a seed is registered there) and the target scope. Whatever
	// makes it step aside (ErrNeedsFullOpen) then comes before the first write, never between storing
	// a seed and registering it (#269 review W1).
	if r.lazy {
		if r.root.Root != "" {
			if err := r.loadScope(r.root.Root); err != nil {
				return w, err
			}
		}
		if spec.Scope != "" {
			if err := r.loadScope(spec.Scope); err != nil {
				return w, err
			}
		}
	}
	if w.CreatedRoot, err = r.Place(&spec, priv); err != nil {
		return w, err
	}
	env, _, err := claim.SignWith(spec, priv)
	if err != nil {
		return w, err
	}
	w.Envelope = env
	if w.ID, w.IsNew, err = r.Add(env); err != nil {
		return w, err
	}
	r.ownAppend(w.ID)
	// A seed this store holds but its root does not list yet is registered, new or not: a write that
	// stored the seed and then failed before registering must not leave it unlisted for good (W1).
	if spec.PredicateType == claim.ScopePredicateType && w.ID != r.root.Root && (w.IsNew || !r.Registered()[w.ID]) {
		by, _ := spec.PredicateBody["by"].(string)
		// A seed with an explicit parent leaves Place nothing to do, but it is still opened in this
		// store and belongs on its root's list: a store without a root gets one first.
		if r.root.Root == "" {
			if w.CreatedRoot, err = r.CreateRoot(priv, by, "", ""); err != nil {
				return w, fmt.Errorf("seed %s is stored, but creating the root to register it in failed: %w", w.ID, err)
			}
		}
		// The registration carries the seed's own time, not the wall clock: with it, a seed written
		// with a fixed --when into a store with a pinned root rebuilds byte for byte (kton-web 19.11.).
		when, _ := spec.PredicateBody["when"].(string)
		if when == "" {
			when = spec.When
		}
		if w.Registered, err = r.RegisterSubnekton(w.ID, priv, by, when); err != nil {
			return w, fmt.Errorf("seed %s is stored, but registering it in the root failed: %w", w.ID, err)
		}
	}
	return w, nil
}
