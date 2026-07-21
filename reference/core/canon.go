// Package core implements the plankton kernel: content addressing, the foton model,
// canonical JSON, and DSSE attestation verification. Pure standard library.
package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// HashBytes returns the multihash-prefixed SHA-256 content address of b (spec §5).
func HashBytes(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// NormalizeContentHash canonicalizes a content-hash string per SPEC §5.1: a content hash is
// "sha256:" + LOWERCASE hex of the 32-byte digest. It accepts an optional "sha256:" prefix (in ANY
// case - "sha256:", "SHA256:", "Sha256:") and a bare 64-hex string, trims surrounding whitespace, and
// lowercases the hex, returning (canonical, true). Anything that is not a well-formed sha256 content
// hash (a URI, a wrong-length or wrong-algorithm string) is returned unchanged with ok=false, so
// callers leave non-hash subjects alone. Normalizing at every identity/index/lookup boundary is what
// makes the SAME digest resolve to the SAME identity - without it, "sha256:ABC..." and "sha256:abc..."
// split into two records and a claim about one is invisible to a consumer resolving the other. The
// prefix is matched case-insensitively so `kton blob`/`fetch` (which lowercase the whole string) and
// the nekton index (which goes through here) agree on "SHA256:..." instead of one accepting it and the
// other rejecting it (cold-session findings: hash-split, and blob-normalize cross-tool inconsistency).
func NormalizeContentHash(s string) (string, bool) {
	h := strings.TrimSpace(s)
	if len(h) >= 7 && strings.EqualFold(h[:7], "sha256:") {
		h = h[7:]
	}
	if len(h) != 64 {
		return s, false
	}
	out := make([]byte, 64)
	for i := 0; i < 64; i++ {
		c := h[i]
		switch {
		case c >= '0' && c <= '9':
			out[i] = c
		case c >= 'a' && c <= 'f':
			out[i] = c
		case c >= 'A' && c <= 'F':
			out[i] = c + ('a' - 'A') // lowercase
		default:
			return s, false // non-hex char: not a content hash
		}
	}
	return "sha256:" + string(out), true
}

// CanonJSON returns RFC 8785 (JCS) canonical JSON for arbitrary JSON input. This is the
// interoperability floor: two independent implementations MUST produce byte-identical output for
// the same logical content, or they compute different hashes and cross-implementation verification
// silently breaks (a valid record reads as tampered). See spec §5.
func CanonJSON(in []byte) ([]byte, error) {
	// I-JSON / RFC 8785 forbid DUPLICATE object names. Go's decoder silently keeps the LAST one, so
	// {"x":"BENIGN","x":"EVIL"} would sign/id as EVIL while a first-wins reader sees BENIGN - equal id,
	// different content-as-read. Reject it BEFORE decoding, so no such record can be canonicalized,
	// signed, or ingested (cold-session canonicalization finding).
	if err := checkNoDupKeys(in); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(in))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := writeCanon(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// checkNoDupKeys walks the JSON token stream and errors if any object has a repeated name (at any
// nesting depth). Streaming, not decode-into-map, precisely because a map silently collapses dups.
func checkNoDupKeys(in []byte) error {
	dec := json.NewDecoder(bytes.NewReader(in))
	dec.UseNumber()
	var walk func() error
	walk = func() error {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := t.(json.Delim); ok {
			switch d {
			case '{':
				seen := map[string]bool{}
				for dec.More() {
					kt, err := dec.Token() // object name
					if err != nil {
						return err
					}
					k, _ := kt.(string)
					if seen[k] {
						return fmt.Errorf("canon: duplicate object name %q (RFC 8785 / I-JSON forbid duplicate names)", k)
					}
					seen[k] = true
					if err := walk(); err != nil { // its value
						return err
					}
				}
				if _, err := dec.Token(); err != nil { // closing '}'
					return err
				}
			case '[':
				for dec.More() {
					if err := walk(); err != nil {
						return err
					}
				}
				if _, err := dec.Token(); err != nil { // closing ']'
					return err
				}
			}
		}
		return nil
	}
	return walk()
}

// CanonValue canonicalizes an in-memory value by round-tripping it through JSON.
func CanonValue(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return CanonJSON(bytes.TrimRight(b.Bytes(), "\n"))
}

func writeCanon(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		// RFC 8785: sort object member names by their UTF-16 code units.
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeJCSString(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeCanon(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		// RFC 8785: array element order is preserved, never sorted.
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanon(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case string:
		return writeJCSString(buf, t)
	case json.Number:
		n, err := jcsNumber(string(t))
		if err != nil {
			return err
		}
		buf.WriteString(n)
	case float64: // only if a caller bypasses UseNumber
		n, err := jcsNumberFloat(t)
		if err != nil {
			return err
		}
		buf.WriteString(n)
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case nil:
		buf.WriteString("null")
	default:
		return fmt.Errorf("canon: unsupported JSON value %T", v)
	}
	return nil
}

// lessUTF16 compares two strings by their UTF-16 code-unit sequences (RFC 8785 §3.2.3). For
// BMP-only strings this coincides with code-point order; it differs only for supplementary
// characters, which UTF-16 represents as surrogate pairs.
func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// writeJCSString serializes a JSON string per RFC 8785 §3.2.2.2: control characters below U+0020
// use the five named short escapes or lowercase \uXXXX; only '"' and '\' are escaped above that;
// everything else (including non-ASCII and '/') is emitted literally as UTF-8. Invalid Unicode is
// rejected (I-JSON / RFC 7493): it leads to inconsistent hashes and broken signatures.
func writeJCSString(buf *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("canon: string is not valid Unicode (I-JSON forbids it)")
	}
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\t':
			buf.WriteString(`\t`)
		case '\n':
			buf.WriteString(`\n`)
		case '\f':
			buf.WriteString(`\f`)
		case '\r':
			buf.WriteString(`\r`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r) // lowercase hex, exactly 4 digits
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
	return nil
}

// jcsNumber serializes a JSON number per RFC 8785 §3.2.2.3 (the ECMAScript Number-to-String
// algorithm). Values are taken through IEEE 754 double; anything needing more precision or range
// than a double can hold MUST be carried as a JSON string, not a number (RFC 8785 Appendix D).
func jcsNumber(s string) (string, error) {
	// An INTEGER literal that does not survive the IEEE-754 double round-trip would silently collide
	// with its neighbour: 9007199254740993 (2^53+1) canonicalizes to 9007199254740992, so two claims
	// differing by 1 share an id. RFC 8785 App D says such a value MUST be carried as a string; reject
	// it as a number rather than sign an ambiguous id (cold-session canonicalization finding).
	if !strings.ContainsAny(s, ".eE") {
		if i, perr := strconv.ParseInt(s, 10, 64); perr == nil {
			if int64(float64(i)) != i {
				return "", fmt.Errorf("canon: integer %s is not exactly representable as an IEEE-754 double (RFC 8785 App D: carry it as a string)", s)
			}
		} else if strings.TrimLeft(strings.TrimPrefix(s, "-"), "0123456789") == "" {
			// a well-formed integer literal too large for int64 - definitely beyond double precision
			return "", fmt.Errorf("canon: integer %s exceeds the exactly-representable range (RFC 8785 App D: carry it as a string)", s)
		}
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return "", fmt.Errorf("canon: number %q not representable as IEEE 754 double: %w", s, err)
	}
	return jcsNumberFloat(f)
}

func jcsNumberFloat(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", fmt.Errorf("canon: NaN/Infinity is not valid JSON")
	}
	if f == 0 {
		return "0", nil // also normalizes -0 to "0"
	}
	neg := math.Signbit(f)
	// Shortest round-tripping significand + exponent, in scientific form: "d[.ddd]e±XX".
	sci := strconv.FormatFloat(math.Abs(f), 'e', -1, 64)
	ei := strings.IndexByte(sci, 'e')
	mant, exp := sci[:ei], 0
	exp, _ = strconv.Atoi(sci[ei+1:])
	digits := mant
	if dot := strings.IndexByte(digits, '.'); dot >= 0 {
		digits = digits[:dot] + digits[dot+1:]
	}
	k := len(digits) // number of significant digits
	n := exp + 1     // position of the decimal point relative to the digits (ECMAScript's n)

	var out string
	switch {
	case k <= n && n <= 21:
		out = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		out = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		out = "0." + strings.Repeat("0", -n) + digits
	default: // n > 21 or n <= -6 : exponential form
		m := digits[:1]
		if k > 1 {
			m += "." + digits[1:]
		}
		e := n - 1
		sign := "+"
		if e < 0 {
			sign, e = "-", -e
		}
		out = m + "e" + sign + strconv.Itoa(e)
	}
	if neg {
		out = "-" + out
	}
	return out, nil
}
