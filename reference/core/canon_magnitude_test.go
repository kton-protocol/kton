package core_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"kton.dev/plankton/core"
)

// The exact-integer check parses the literal with big.Rat, which for `1e-1000000` builds a
// denominator of 10^1000000 - hundreds of kilobytes of digits - for a value ParseFloat has already
// underflowed to zero. Ingest and verify canonicalize externally supplied payloads, so work decided
// by an exponent's VALUE rather than by the input's SIZE is an amplifier: a four-figure document
// took seconds.
//
// The assertion is on WORK, not on wall-clock: a timing threshold is a property of the machine that
// runs it. A tiny-exponent document must cost about what an ordinary one of the same size costs, and
// the ratio is what a reader can trust on any machine. The generous factor keeps it from flaking on
// a loaded CI runner while still failing by three orders of magnitude on the old code.
func TestCanonWorkDoesNotScaleWithExponentValue(t *testing.T) {
	doc := func(num string) []byte {
		return []byte("[" + strings.TrimSuffix(strings.Repeat(num+",", 100), ",") + "]")
	}
	measure := func(b []byte) time.Duration {
		best := time.Hour
		for i := 0; i < 3; i++ { // best of three: we want the floor, not the scheduler's noise
			t0 := time.Now()
			if _, err := core.CanonJSON(b); err != nil {
				t.Fatalf("canon refused a well-formed document: %v", err)
			}
			if d := time.Since(t0); d < best {
				best = d
			}
		}
		return best
	}

	ordinary := measure(doc("1.5"))
	for _, num := range []string{"1e-1000000", "1e-100000", "-2.5e-500000"} {
		tiny := measure(doc(num))
		if tiny > 100*ordinary+50*time.Millisecond {
			t.Errorf("%s: %v vs %v for ordinary numbers of the same size - the exponent's value, "+
				"not the input's size, is deciding the work", num, tiny, ordinary)
		}
	}
}

// The bound must not cost the check its job: every spelling that was refused before is still
// refused, and everything legitimate still passes.
func TestExactIntegerRangeStillEnforced(t *testing.T) {
	refused := []string{
		"9007199254740993",       // 2^53+1: rounds to 2^53, so only the exact parse catches it
		"100000000000000000000",  // plain large integer
		"1e20",                   // the same value in exponent form
		"9007199254740993.0",     // integer value written as a float
		"12345678901234567890.5", // not an integer literal; its double IS a huge integer
		"-9007199254740993",      // sign must not matter
		"0.9007199254740993e17",  // magnitude carried entirely by the exponent
	}
	for _, n := range refused {
		if _, err := core.CanonJSON([]byte("[" + n + "]")); err == nil {
			t.Errorf("%s was accepted; it is outside the exactly-representable range", n)
		}
	}
	accepted := []string{
		"9007199254740992", // exactly 2^53
		"-9007199254740992",
		"1.5", "0", "-0.0", "1e-30", "1e-1000000", "0.1", "123456789012345",
		"0.0000001e9", // magnitude 3 despite the exponent - leading zeros are not significant
	}
	for _, n := range accepted {
		out, err := core.CanonJSON([]byte("[" + n + "]"))
		if err != nil {
			t.Errorf("%s was refused: %v", n, err)
			continue
		}
		// canon(canon(x)) == canon(x): an accepted input must not produce output this same function
		// then refuses.
		again, err := core.CanonJSON(out)
		if err != nil || string(again) != string(out) {
			t.Errorf("%s is not idempotent: %s -> %s (%v)", n, out, again, err)
		}
		var v any
		if err := json.Unmarshal(out, &v); err != nil {
			t.Errorf("%s produced invalid JSON: %s", n, out)
		}
	}
}
