package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestQueryCommandsRefuseLastWins: the positional hardening reached nekton's `annotate`, `attach` and
// `material` and stopped at the kernel boundary — in the very change that was fixing a
// plankton/nekton twin. plankton's query commands still took the LAST positional:
//
//	plankton producer <a> <b>       answered about <b>
//	plankton material <a> <b>       answered about <b>
//	plankton reproduces <a> <b> <c> compared <a> against <c>
//
// A question the caller did not ask, answered with no sign that the first argument was dropped. The
// §12 clause quoted in main.go rules out an empty answer to a malformed question for the same
// reason: answering the WRONG question is not better than answering a malformed one.
func TestQueryCommandsRefuseLastWins(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PLANKTON_DIR", filepath.Join(dir, "reg"))
	a := "sha256:" + strings.Repeat("a", 64)
	b := "sha256:" + strings.Repeat("b", 64)
	ev := filepath.Join(dir, "ev.bin")
	if err := os.WriteFile(ev, []byte("evidence"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		cmd  string
		args []string
		want string
	}{
		{"producer, two ids", "producer", []string{a, b}, "takes ONE"},
		{"uses, two ids", "uses", []string{a, b}, "takes ONE"},
		{"lineage, two ids", "lineage", []string{a, b}, "takes ONE"},
		{"material, two ids", "material", []string{a, b}, "takes ONE"},
		{"producer, single-dash flag", "producer", []string{a, "-x"}, "unknown flag"},
		{"attach, single-dash flag", "attach", []string{a, "-x", "--scheme", "rekor-entry", "--file", ev},
			"unknown flag"},
		{"material, single-dash flag", "material", []string{a, "-x"}, "unknown flag"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := run(tc.cmd, tc.args)
			if err == nil {
				t.Fatalf("plankton %s accepted it and answered about the wrong argument", tc.cmd)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("wrong refusal: %v", err)
			}
		})
	}

	// The forms that were always correct must still work. A gate that refuses the normal path is the
	// failure this repository keeps finding, including in the commit this one is fixing.
	t.Run("one argument still works", func(t *testing.T) {
		for _, cmd := range []string{"producer", "uses", "lineage", "material"} {
			if err := run(cmd, []string{a}); err != nil {
				t.Errorf("plankton %s with one id was refused: %v", cmd, err)
			}
		}
		// NOT `reproduces` here: with two well-formed hashes it reaches its verdict path, which
		// signals "not reproduced" with os.Exit(1) - so an in-process call kills the test binary
		// before the framework reports anything. Its argument check is covered by the
		// three-hashes case above, which returns before that path.
	})
}

// TestReproducesRefusesAThirdHash needs a SUBPROCESS, and the reason is worth stating: with two
// well-formed hashes `reproduces` reaches its verdict path and signals "not reproduced" with
// os.Exit(1). So if the argument guard were removed, an in-process call would kill the test binary
// instead of returning an error - and the run would report nothing at all rather than a failure.
//
// That is a check that cannot fail, which is the defect this repository keeps finding. The first
// version of this test had it. Running the guard in a child process is what makes the assertion
// real: a refusal and a verdict are different exits, and the parent can tell them apart.
func TestReproducesRefusesAThirdHash(t *testing.T) {
	if os.Getenv("KTON_REPRO_ARG_CHILD") == "1" {
		// In the child: exercise the parse and let whatever happens, happen.
		a := "sha256:" + strings.Repeat("a", 64)
		b := "sha256:" + strings.Repeat("b", 64)
		c := "sha256:" + strings.Repeat("c", 64)
		if err := run("reproduces", []string{a, b, c}); err != nil {
			os.Stderr.WriteString(err.Error())
			os.Exit(7) // a distinct code: this is the REFUSAL, not the verdict
		}
		os.Exit(0)
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestReproducesRefusesAThirdHash")
	cmd.Env = append(os.Environ(), "KTON_REPRO_ARG_CHILD=1",
		"PLANKTON_DIR="+filepath.Join(t.TempDir(), "reg"))
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("running the child: %v\n%s", err, out)
	}
	if code != 7 {
		t.Fatalf("a third hash was not refused (child exit %d) - it used to replace the candidate "+
			"silently, so the verdict was about a different pair than the one asked for\n%s", code, out)
	}
	if !strings.Contains(string(out), "compares TWO") {
		t.Errorf("the refusal does not say what the command takes: %s", out)
	}
}
