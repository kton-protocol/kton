package claim_test

import (
	"strings"
	"testing"

	"kton.dev/nekton/claim"
)

// ValidateChainStructure is the ONE definition of the context-free half of SPEC §7.4, called from
// both the registry's chain check and `nekton verify`. It has to stay one: `verify` never reaches a
// registry, so a second copy there is how the two commands come to disagree about what a storable
// record is - and `verify` exit 0 promises "genuine AND storable".
//
// These are the rules that need no registry state. Whether a scope RESOLVES and whether a `prev`
// links to something present are context-dependent and deliberately stay with the registry.
func TestValidateChainStructure(t *testing.T) {
	seed := func(p claim.Predicate) (*claim.Statement, *claim.Predicate) {
		return &claim.Statement{PredicateType: claim.ScopePredicateType}, &p
	}
	ordinary := func(p claim.Predicate) (*claim.Statement, *claim.Predicate) {
		return &claim.Statement{PredicateType: claim.PredicateType}, &p
	}

	t.Run("a seed must set genesis", func(t *testing.T) {
		st, p := seed(claim.Predicate{Scope: "review"})
		if err := claim.ValidateChainStructure(st, p); err == nil {
			t.Error("a scope/v0 seed with genesis:false was accepted")
		} else if !strings.Contains(err.Error(), "genesis:true") {
			t.Errorf("refused for the wrong reason: %v", err)
		}
	})

	t.Run("a seed must not carry prev", func(t *testing.T) {
		st, p := seed(claim.Predicate{Scope: "review", Genesis: true, Prev: "sha256:" + strings.Repeat("a", 64)})
		if err := claim.ValidateChainStructure(st, p); err == nil {
			t.Error("a seed carrying prev was accepted - it opens the chain, it cannot continue one")
		}
	})

	t.Run("genesis is a seed-only flag", func(t *testing.T) {
		st, p := ordinary(claim.Predicate{Genesis: true})
		if err := claim.ValidateChainStructure(st, p); err == nil {
			t.Error("genesis:true on a claim/v0 was accepted - that mints a scope without a scope/v0 statement")
		}
	})

	t.Run("top-level genesis is never valid", func(t *testing.T) {
		st := &claim.Statement{PredicateType: claim.PredicateType, Genesis: true}
		if err := claim.ValidateChainStructure(st, &claim.Predicate{}); err == nil {
			t.Error("a top-level genesis field was accepted; it must live inside a scope/v0 predicate")
		}
	})

	t.Run("the legitimate shapes pass", func(t *testing.T) {
		st, p := seed(claim.Predicate{Scope: "review", Genesis: true})
		if err := claim.ValidateChainStructure(st, p); err != nil {
			t.Errorf("a well-formed seed was refused: %v", err)
		}
		st, p = ordinary(claim.Predicate{Scope: "review", Prev: "sha256:" + strings.Repeat("b", 64)})
		if err := claim.ValidateChainStructure(st, p); err != nil {
			t.Errorf("a well-formed scoped claim was refused: %v", err)
		}
	})
}
