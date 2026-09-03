package main

// records.go answers the §12 `sync(since)` query over stdout, the nekton half of #85.
//
// Same reasoning as plankton's: §12 fixes the queries and the wire form and leaves the transport
// unspecified (Annex C describes an HTTP realization; #83 removed the server that spoke it). The
// shape is what the kernel already persists and what `add` accepts - {seq, claimId, envelope}.

import (
	"fmt"
	"strconv"
	"strings"

	"kton.dev/nekton/registry"
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
			return fmt.Errorf("usage: nekton records [--json] [--since <cursor>]")
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
		// `max` is the cursor to pass back next time - the registry's, not the last record's seq,
		// so an empty batch still advances a caller past what it has seen.
		return printJSONOut(map[string]any{"records": recs, "max": r.MaxSeq()})
	}
	if len(recs) == 0 {
		fmt.Printf("(none) - no records above cursor %d (registry cursor is %d)\n", since, r.MaxSeq())
		return nil
	}
	for _, rec := range recs {
		fmt.Printf("%6d  %s  sigs=%d\n", rec.Seq, rec.ClaimID, len(rec.Envelope.Signatures))
	}
	fmt.Printf("cursor: %d  (pass --since %d to get only what is newer)\n", r.MaxSeq(), r.MaxSeq())
	return nil
}
