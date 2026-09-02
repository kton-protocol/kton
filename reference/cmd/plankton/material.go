package main

// material.go is the CLI face of SPEC §8.1 for plankton: attach external evidence to a foton, and
// read back what is attached. Mirrors `nekton attach` / `nekton material` deliberately - a flag
// that behaves differently on the two kernels would be its own trap.

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"kton.dev/plankton/core"
	"kton.dev/plankton/registry"
)

// schemeHint maps the tokens SPEC §8.1 lists to their usual media type. An UNKNOWN scheme is fine
// and needs --media: refusing unknown evidence would make this list a protocol version.
var schemeHint = map[string]string{
	"sigstore-bundle": "application/vnd.dev.sigstore.bundle.v1+json",
	"rekor-entry":     "application/json",
	"rfc3161":         "application/timestamp-reply",
	"cms-detached":    "application/pkcs7-signature",
	"jades":           "application/jose+json",
	"pgp-detached":    "application/pgp-signature",
}

func attachMaterial(args []string) error {
	var subject, scheme, media, file string
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
		return fmt.Errorf("usage: plankton attach <sha256:fotonId> --scheme <s> --file <evidence> [--media <type>]\n" +
			"  schemes (SPEC §8.1; the list is open, an unknown one needs --media):\n" +
			"    sigstore-bundle  rekor-entry  rfc3161  cms-detached  jades  pgp-detached")
	}
	if media == "" {
		hint, ok := schemeHint[scheme]
		if !ok {
			return fmt.Errorf("scheme %q is not one of the listed tokens - pass --media <type> so a reader knows how to read the evidence", scheme)
		}
		media = hint
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	if n, ok := core.NormalizeContentHash(subject); ok {
		subject = n
	}
	r, err := registry.Open(dir())
	if err != nil {
		return err
	}
	if err := r.AttachMaterial(registry.VerificationMaterial{
		Subject: subject, Scheme: scheme, MediaType: media,
		Material: base64.StdEncoding.EncodeToString(b),
	}); err != nil {
		return err
	}
	fmt.Printf("attached %s (%d bytes, %s) to %s\n", scheme, len(b), media, subject)
	fmt.Fprintln(os.Stderr, "note: stored, NOT verified - the kernel never evaluates verification material (SPEC §8.1); a consumer decides which issuers count")
	return nil
}

func listMaterial(args []string) error {
	asJSON := false
	subject := ""
	for _, a := range args {
		switch {
		case a == "--json":
			asJSON = true
		case strings.HasPrefix(a, "--"):
			return fmt.Errorf("unknown flag %q", a)
		default:
			subject = a
		}
	}
	if subject == "" {
		return fmt.Errorf("usage: plankton material <sha256:fotonId> [--json]")
	}
	if n, ok := core.NormalizeContentHash(subject); ok {
		subject = n
	}
	r, err := registry.Open(dir())
	if err != nil {
		return err
	}
	mats := r.Material(subject)

	if asJSON {
		out := make([]map[string]any, 0, len(mats))
		for _, m := range mats {
			// Bytes go out as stored. The kernel does not decode, interpret or verify them.
			out = append(out, map[string]any{
				"subject": m.Subject, "scheme": m.Scheme,
				"mediaType": m.MediaType, "material": m.Material, "verified": false,
			})
		}
		return printJSON(map[string]any{"subject": subject, "material": out})
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
