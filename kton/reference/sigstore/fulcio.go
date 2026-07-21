package sigstore

import "fmt"

// DefaultFulcioURL is the public Sigstore Fulcio certificate authority.
const DefaultFulcioURL = "https://fulcio.sigstore.dev"

// KeylessAnchor is a SCAFFOLD for the Fulcio keyless path - deliberately not wired yet.
//
// Fulcio issues a short-lived signing certificate bound to an OIDC identity; obtaining the OIDC
// token requires an interactive browser flow (or an ambient CI/workload token). That interactivity
// is exactly why keyless is deferred - the Rekor anchor (rekor.go) is headless and already live.
//
// Intended flow when wired:
//  1. obtain an OIDC id-token (browser/device-code, or ambient) for the signer identity;
//  2. generate an ephemeral keypair; POST a CSR + token to Fulcio → a short-lived X.509 cert;
//  3. sign the DSSE payload with the ephemeral key;
//  4. Anchor() the envelope to Rekor with the cert as verifier (the identity travels in the cert).
//
// For regulated (21 CFR Part 11) signing, prefer org PKI/X.509 as the durable `by` identity and
// use Rekor purely as the transparency anchor - keyless fits the public/open-federation edge, not
// internal sign-offs. See docs/attestation.md and the Sigstore evaluation notes.
func KeylessAnchor(_ string) error {
	return fmt.Errorf("Fulcio keyless signing is scaffolded but not wired yet: it needs an interactive OIDC login. " +
		"Use the headless Ed25519 + Rekor anchor path for now (plankton anchor)")
}
