package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kton.dev/plankton/core"
)

func TestPositionChangesOnlyWhenTheStoreDoes(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PLANKTON_DIR", filepath.Join(dir, "reg"))
	if err := keygen([]string{filepath.Join(dir, "k"), "--seed", strings.Repeat("5a", 32)}); err != nil {
		t.Fatal(err)
	}
	pos := func() core.Position {
		t.Helper()
		var p core.Position
		raw := captureStdout(t, func() {
			if err := run("position", []string{"--json"}); err != nil {
				t.Fatal(err)
			}
		})
		if err := json.Unmarshal([]byte(raw), &p); err != nil {
			t.Fatalf("position --json: %v\n%s", err, raw)
		}
		return p
	}
	add := func(content string) {
		t.Helper()
		in, out := filepath.Join(dir, "in.txt"), filepath.Join(dir, content+".txt")
		for p, b := range map[string]string{in: "a", out: content} {
			if err := os.WriteFile(p, []byte(b), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := run("author", []string{"--cmd", "run", "--in", in, "--out", out, "--sign", filepath.Join(dir, "k.key"), "--add"}); err != nil {
			t.Fatal(err)
		}
	}
	add("one")
	a := pos()
	if a.Epoch == "" || a.MaxSeq != 1 {
		t.Errorf("after one add: %+v", a)
	}
	if b := pos(); b != a {
		t.Errorf("position moved with nothing written: %+v vs %+v", b, a)
	}
	add("two")
	if c := pos(); c.Objects == a.Objects || c.MaxSeq != 2 || c.Epoch != a.Epoch {
		t.Errorf("after a second add: %+v (before %+v)", c, a)
	}
}
