package main

// material.go is the CLI face of SPEC §8.1: attach external evidence to a record, and read back
// what is attached. The kernel never evaluates any of it - it stores opaque bytes and says who
// claimed to produce them, exactly as it stores a DSSE signature without verifying it on ingest.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"kton.dev/nekton/registry"
)

// schemeHint maps the tokens SPEC §8.1 lists to their usual media type, so a caller that names a
// known scheme need not repeat it. An UNKNOWN scheme is fine and needs --media: refusing unknown
// evidence would make this list a protocol version, which is what §8.1 exists to avoid.
var schemeHint = map[string]string{
	"sigstore-bundle": "application/vnd.dev.sigstore.bundle.v1+json",
	"rekor-entry":     "application/json",
	"rfc3161":         "application/timestamp-reply",
	"cms-detached":    "application/pkcs7-signature",
	"jades":           "application/jose+json",
	"pgp-detached":    "application/pgp-signature",
}

// attachMaterial: nekton attach <sha256:id> --scheme S [--media M] --file F [--registry D]
func attachMaterial(args []string) error {
	var subject, scheme, media, file, regDir string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--scheme":
			i++
			scheme = arg(args, i)
		case "--media":
			i++
			media = arg(args, i)
		case "--file":
			i++
			file = arg(args, i)
		case "--registry":
			i++
			regDir = arg(args, i)
		default:
			if strings.HasPrefix(args[i], "--") {
				return fmt.Errorf("unknown flag %q", args[i])
			}
			if subject != "" {
				return fmt.Errorf("attach takes one subject, got %q and %q", subject, args[i])
			}
			subject = args[i]
		}
	}
	if subject == "" || scheme == "" || file == "" {
		return fmt.Errorf("usage: nekton attach <sha256:claimId> --scheme <s> --file <evidence> [--media <type>] [--registry D]\n" +
			"  schemes (SPEC §8.1; the list is open, an unknown one needs --media):\n" +
			"    sigstore-bundle  rekor-entry  rfc3161  cms-detached  jades  pgp-detached")
	}
	if media == "" {
		if hint, ok := schemeHint[scheme]; ok {
			media = hint
		} else {
			return fmt.Errorf("scheme %q is not one of the listed tokens - pass --media <type> so a reader knows how to read the evidence", scheme)
		}
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	r, err := registry.Open(regOrDefault(regDir))
	if err != nil {
		return err
	}
	vm := registry.VerificationMaterial{
		Subject:   subject,
		Scheme:    scheme,
		MediaType: media,
		Material:  base64.StdEncoding.EncodeToString(b),
	}
	if err := r.AttachMaterial(vm); err != nil {
		return err
	}
	fmt.Printf("attached %s (%d bytes, %s) to %s\n", scheme, len(b), media, subject)
	fmt.Fprintln(os.Stderr, "note: stored, NOT verified - the kernel never evaluates verification material (SPEC §8.1); a consumer decides which issuers count")
	return nil
}

// listMaterial: nekton material <sha256:id> [--json] [--registry D]
func listMaterial(args []string) error {
	rest, asJSON := takeJSON(args)
	var subject, regDir string
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "--registry":
			i++
			regDir = arg(rest, i)
		default:
			if strings.HasPrefix(rest[i], "--") {
				return fmt.Errorf("unknown flag %q", rest[i])
			}
			subject = rest[i]
		}
	}
	if subject == "" {
		return fmt.Errorf("usage: nekton material <sha256:claimId> [--json] [--registry D]")
	}
	r, err := registry.Open(regOrDefault(regDir))
	if err != nil {
		return err
	}
	mats := r.Material(subject)

	if asJSON {
		out := make([]map[string]any, 0, len(mats))
		for _, m := range mats {
			// The bytes go out as stored (base64). The kernel does not decode, interpret or verify
			// them; a consumer that knows the scheme does.
			out = append(out, map[string]any{
				"subject": m.Subject, "scheme": m.Scheme,
				"mediaType": m.MediaType, "material": m.Material, "verified": false,
			})
		}
		b, err := json.MarshalIndent(map[string]any{"subject": subject, "material": out}, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}

	if len(mats) == 0 {
		fmt.Printf("(none) - no verification material attached to %s\n", subject)
		return nil
	}
	for _, m := range mats {
		raw, _ := base64.StdEncoding.DecodeString(m.Material)
		fmt.Printf("%-16s %-46s %d bytes\n", m.Scheme, m.MediaType, len(raw))
	}
	fmt.Fprintln(os.Stderr, "note: listed, NOT verified - evaluating this evidence is a consumer's job, not the kernel's (SPEC §8.1)")
	return nil
}
