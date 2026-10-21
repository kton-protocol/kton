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

// A dangling symlink named like a record is skipped and counted, like a corrupt one, instead of
// failing the whole Open (#236).
func TestOpenSkipsADanglingRecordLink(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"name": "out", "digest": map[string]any{"sha256": strings.Repeat("44", 32)}}},
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

	dir := t.TempDir()
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Add(env); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "objects", "sha256", strings.Repeat("ee", 32)+".json")
	if err := os.Symlink(filepath.Join(dir, "nowhere.json"), link); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	again, err := Open(dir)
	if err != nil {
		t.Fatalf("one dangling link failed the whole Open: %v", err)
	}
	if again.Len() != 1 || again.Degraded() != 1 {
		t.Errorf("Len %d, Degraded %d; want 1 and 1", again.Len(), again.Degraded())
	}
}
