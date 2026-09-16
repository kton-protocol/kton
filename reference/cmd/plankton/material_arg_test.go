package main

import (
	"strings"
	"testing"
)

// The plankton half of the same §12 rule: "An unrecognised or absent query parameter MUST be an
// error, never an empty result: an empty answer to a malformed question is a successful wrong
// answer." `plankton material -x` answered "(none) - no verification material attached to -x" and
// exited 0, so a caller asking whether a foton carries evidence was told "checked, none there"
// about a string that is not a foton id at all.
func TestMaterialRefusesAMalformedFotonID(t *testing.T) {
	t.Setenv("PLANKTON_DIR", t.TempDir())
	for _, bad := range []string{"-x", "not-a-hash", "sha256:abc"} {
		if err := listMaterial([]string{bad}); err == nil {
			t.Errorf("material %q answered instead of refusing", bad)
		}
	}
	// A well-formed id with nothing attached stays a plain answer, not an error - the record could
	// have material and does not. A gate that refuses the normal path is the failure this
	// repository keeps finding.
	if err := listMaterial([]string{"sha256:" + strings.Repeat("ab", 32)}); err != nil {
		t.Errorf("a well-formed id with no material was refused: %v", err)
	}
}
