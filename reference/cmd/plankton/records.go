package main

// records.go answers the §12 `sync(since)` query over stdout.
//
// §12 fixes the QUERIES and the wire form and leaves the transport unspecified; Annex C describes
// an HTTP realization, and #83 removed the server that spoke it. This is the other binding, and it
// is what makes the reference implementation answer its own Clause 12 again.
//
// The shape is deliberately not new: {seq, fotonId, envelope} is what the kernel already persists,
// what `add` accepts, and byte-for-byte the sync answer. reference/testdata/federation/ is generated
// from this command, so the conformance fixture and the implementation cannot drift.

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"kton.dev/plankton/registry"
)

func records(args []string) error {
	asJSON, since := false, 0
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			asJSON = true
		case "--since":
			i++
			n, err := strconv.Atoi(arg(args, i))
			if err != nil {
				return fmt.Errorf("--since expects a cursor (an integer), got %q", arg(args, i))
			}
			since = n
		default:
			if strings.HasPrefix(args[i], "--") {
				return fmt.Errorf("unknown flag %q", args[i])
			}
			return fmt.Errorf("usage: plankton records [--json] [--since <cursor>]")
		}
	}
	r, err := registry.Open(dir())
	if err != nil {
		return err
	}
	recs := r.Records(since)
	if recs == nil {
		recs = []registry.Record{}
	}

	if asJSON {
		// `max` is the cursor to pass back as --since next time. It is the registry's max, not the
		// last record's seq: a caller must advance past what it has SEEN, and an empty batch still
		// moves the cursor forward.
		return printJSON(map[string]any{"records": recs, "max": r.MaxSeq()})
	}
	if len(recs) == 0 {
		fmt.Printf("(none) - no records above cursor %d (registry cursor is %d)\n", since, r.MaxSeq())
		return nil
	}
	for _, rec := range recs {
		n := 0
		if f, ok := r.Foton(rec.FotonID); ok {
			n = len(f.Outputs)
		}
		fmt.Printf("%6d  %s  out=%d  sigs=%d\n", rec.Seq, rec.FotonID, n, len(rec.Envelope.Signatures))
	}
	fmt.Printf("cursor: %d  (pass --since %d to get only what is newer)\n", r.MaxSeq(), r.MaxSeq())
	return nil
}

var _ = json.Marshal
