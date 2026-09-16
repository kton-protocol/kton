package main

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"kton.dev/plankton/core"
)

// --environment and --env-ref ride in Protocol.Descriptor and are COVERED (SPEC §6.5): they change
// the foton id. show printed only `cmd`, and the branch that would have shown the rest of the
// descriptor sat behind an `else if` that author's always-set cmd made unreachable - so three
// fotons with the same inputs, outputs and cmd but different environments printed identically,
// and a peer could not see what a reproduction commits to (#54).
func TestShowRendersTheWholeDescriptor(t *testing.T) {
	f := &core.Foton{
		Inputs:  []core.FileRef{{Path: "in.txt", Hash: "sha256:" + strings.Repeat("a", 64)}},
		Outputs: []core.FileRef{{Path: "out.txt", Hash: "sha256:" + strings.Repeat("b", 64)}},
		Protocol: core.Protocol{
			Kind: "script",
			Ref:  "sha256:" + strings.Repeat("c", 64),
			Descriptor: map[string]any{
				"cmd":          "run",
				"environment":  "sha256:" + strings.Repeat("d", 64),
				"envRef":       "docker://sha256:aaaa",
				"somethingNew": "must not vanish either",
			},
		},
	}

	out := captureStdout(t, func() {
		if err := showHuman("sha256:"+strings.Repeat("e", 64), f, core.Envelope{}); err != nil {
			t.Fatal(err)
		}
	})

	for _, want := range []string{"run", "docker://sha256:aaaa", strings.Repeat("d", 64), "must not vanish either"} {
		if !strings.Contains(out, want) {
			t.Errorf("show omitted %q:\n%s", want, out)
		}
	}
	// The environment is part of the identity, and saying so is the point - a reader who cannot tell
	// a covered field from a carried one cannot tell what a reproduction commits to.
	if !strings.Contains(out, "COVERED") {
		t.Errorf("show does not mark the environment as identity-bearing:\n%s", out)
	}
}

// --json exists so a consumer does not parse the prose (the argument #39 made for nekton about/by).
// The descriptor goes out whole: no field of it can be invisible here, because none are named.
func TestShowJSONCarriesTheDescriptorWhole(t *testing.T) {
	f := &core.Foton{
		Protocol: core.Protocol{Kind: "script", Descriptor: map[string]any{"cmd": "run", "envRef": "oci://x"}},
	}
	out := captureStdout(t, func() {
		if err := showJSON("sha256:"+strings.Repeat("e", 64), f, core.Envelope{}); err != nil {
			t.Fatal(err)
		}
	})
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("--json did not emit valid JSON: %v\n%s", err, out)
	}
	proto, _ := got["protocol"].(map[string]any)
	desc, _ := proto["descriptor"].(map[string]any)
	if desc["envRef"] != "oci://x" || desc["cmd"] != "run" {
		t.Errorf("descriptor did not survive --json: %v", desc)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = old
	b, _ := io.ReadAll(r)
	return string(b)
}
