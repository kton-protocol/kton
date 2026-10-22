package registry

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kton.dev/plankton/core"
)

func signedFoton(t *testing.T, out string) core.Envelope {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"name": "out", "digest": map[string]any{"sha256": strings.Repeat(out, 32)}}},
		"predicateType": core.PredicateFoton,
		"predicate": map[string]any{
			"inputs":   []any{map[string]any{"name": "in", "digest": map[string]any{"sha256": strings.Repeat("11", 32)}}},
			"protocol": map[string]any{"kind": "run", "ref": "sha256:" + strings.Repeat("aa", 32)},
		},
	}
	payload, _ := core.CanonValue(st)
	env := core.Envelope{PayloadType: core.PayloadType, Payload: base64.StdEncoding.EncodeToString(payload)}
	env.Signatures = append(env.Signatures, struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	}{core.KeyIDHex(priv.Public().(ed25519.PublicKey)), base64.StdEncoding.EncodeToString(ed25519.Sign(priv, core.PAE(core.PayloadType, payload)))})
	return env
}

// Whatever Open reads moves the position: here a record planted under a dot directory, as a git merge
// can bring it (review of #234, P1). And re-adding what is stored moves nothing (P2).
func TestPositionFollowsWhatOpenReads(t *testing.T) {
	dir := t.TempDir()
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	env := signedFoton(t, "22")
	if _, _, err := r.Add(env); err != nil {
		t.Fatal(err)
	}
	before, _ := ReadPosition(dir)
	if _, _, err := r.Add(env); err != nil {
		t.Fatal(err)
	}
	if again, _ := ReadPosition(dir); again != before {
		t.Errorf("re-adding a stored record moved the position: %+v vs %+v", again, before)
	}

	other := t.TempDir()
	o, _ := Open(other)
	id, _, err := o.Add(signedFoton(t, "33"))
	if err != nil {
		t.Fatal(err)
	}
	src := objectPath(filepath.Join(other, "objects"), id)
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(dir, "objects", ".h", filepath.Base(src))
	os.MkdirAll(filepath.Dir(planted), 0o755)
	os.WriteFile(planted, b, 0o644)
	reopened, _ := Open(dir)
	after, _ := ReadPosition(dir)
	if reopened.Len() == r.Len() {
		t.Skip("Open does not read records under a dot directory here; nothing for the position to see")
	}
	if after.Objects == before.Objects {
		t.Errorf("Open reads %d records (was %d), the position did not change", reopened.Len(), r.Len())
	}
}
