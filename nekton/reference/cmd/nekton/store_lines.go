package main

import (
	"encoding/json"
	"fmt"
	"io"

	"kton.dev/nekton/registry"
)

// storeLinesReport is `nekton verify --store` (#287): it names each store line that Open skips and
// Unreadable() counts. The store is read, never changed: repairing it is the person's decision.
// It returns how many lines it named; the caller exits 5 when there are any, a code of its own,
// because verify's 1-4 describe one record and this is about bytes that are no record at all.
func storeLinesReport(w io.Writer, regDir string, asJSON bool) (int, error) {
	bad, err := registry.UnreadableLines(regDir)
	if err != nil {
		return 0, err
	}
	switch {
	case asJSON:
		if bad == nil {
			bad = []registry.UnreadableLine{}
		}
		enc := json.NewEncoder(w) // no HTML escaping: a "<<<<<<<" marker reads as itself
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(map[string]any{"unreadable": bad}); err != nil {
			return 0, err
		}
	case len(bad) == 0:
		fmt.Fprintln(w, "store:       every line parses as a record")
	default:
		fmt.Fprintf(w, "store:       %d line(s) do not parse as a record and are skipped on open\n", len(bad))
		for _, l := range bad {
			fmt.Fprintf(w, "  %s:%d (byte %d): %s\n      starts %q\n", l.File, l.Line, l.Offset, l.Err, l.Head)
		}
	}
	return len(bad), nil
}
