package registry

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// UnreadableLine is one store line that does not parse as a record: one of the lines that
// Unreadable() counts (#287). It says where the line is, so a person can repair the store by hand,
// for example by removing a torn tail or a merge-conflict marker, and bring the count back to 0.
type UnreadableLine struct {
	File   string `json:"file"`   // the subnekton file, relative to the registry directory, with "/"
	Line   int    `json:"line"`   // 1-based line number in that file
	Offset int64  `json:"offset"` // byte offset of the line's first byte in that file
	Head   string `json:"head"`   // the line's first bytes, as stored (at most unreadableHeadBytes)
	Err    string `json:"error"`  // why it does not parse
}

const unreadableHeadBytes = 80

// UnreadableLines lists the store lines in dir that do not parse as a record, in file order and
// line order. It reads the files directly, without opening the registry, so it also works on a
// store that Open would refuse because of what it lists. It applies the same rule as Open: a blank
// line is skipped, and any other line that is not one JSON record is unreadable. A store with no
// objects directory has no unreadable lines.
func UnreadableLines(dir string) ([]UnreadableLine, error) {
	objectsDir := filepath.Join(dir, "objects")
	var files, legacy []string
	if err := filepath.WalkDir(objectsDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		switch {
		case d.IsDir():
		case strings.HasSuffix(p, ".nekton.jsonl"):
			files = append(files, p)
		case legacyLayout.MatchString(filepath.ToSlash(p)):
			legacy = append(legacy, p)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if len(legacy) > 0 {
		return nil, legacyLayoutError(objectsDir, len(legacy), legacy[0])
	}
	sort.Strings(files)
	var out []UnreadableLine
	for _, p := range files {
		b, err := readFileShared(p)
		if err != nil {
			return nil, err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			rel = p
		}
		var off int64
		for i, raw := range strings.Split(string(b), "\n") {
			start := off
			off += int64(len(raw)) + 1
			line := strings.TrimSpace(raw)
			if line == "" {
				continue
			}
			if err := parseRecordLine(line, &objectFile{}); err != nil {
				head := line
				if len(head) > unreadableHeadBytes {
					head = head[:unreadableHeadBytes]
				}
				out = append(out, UnreadableLine{File: filepath.ToSlash(rel), Line: i + 1,
					Offset: start, Head: head, Err: err.Error()})
			}
		}
	}
	return out, nil
}

// parseRecordLine is the one rule for whether a store line is a record. readSubnektonFor and
// UnreadableLines both use it, so the count and the list cannot drift apart.
func parseRecordLine(line string, of *objectFile) error {
	return json.Unmarshal([]byte(line), of)
}
