package main

// fetch.go is the RESOLVER - the one place a URI is dereferenced. It belongs in kton and only
// in kton: plankton and nekton are strictly neutral, they CARRY a URI as an opaque signed
// string and never execute it (no git/http resolver in the kernels). A location is a signed
// nekton `located-at` claim (subject = content hash, object = uri); kton reads those claims,
// dereferences each suggested URI via a resolver backend that lives here, and verifies
// sha256(bytes) == hash before trusting a byte. Multiple claims = multiple signed suggestions.

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"encoding/json"

	"kton.dev/nekton/claim"
	nreg "kton.dev/nekton/registry"
	"kton.dev/plankton/blobstore"
	"kton.dev/plankton/core"
)

// LocatedAtTerm is the predicate IRI kton recognizes as "this content hash is retrievable at
// this URI" - the published DCAT term dcat:downloadURL, reused rather than minting our own
// (docs/decisions.md §20). It is a CONVENTION the cockpit knows; the kernels never interpret it.
const LocatedAtTerm = "http://www.w3.org/ns/dcat#downloadURL"

// fetch resolves a content hash to its bytes via signed located-at claims, verifies, and pins.
func fetch(hash string, trustKeysDir string, allowLocal bool) error {
	hash = normalizeHash(hash)
	var trusted []ed25519.PublicKey
	if trustKeysDir != "" {
		var kerr error
		if trusted, kerr = loadTrustKeys(trustKeysDir); kerr != nil {
			return kerr
		}
		if len(trusted) == 0 {
			return fmt.Errorf("--trust-keys %s holds no *.pub keys; refusing to dereference on an empty trust policy", trustKeysDir)
		}
	}
	r, err := nreg.Open(nektonDir())
	if err != nil {
		return err
	}
	locs := locatedAt(r, hash, trusted)
	if len(locs) == 0 {
		return fmt.Errorf("no located-at claim for %s in %s (nothing suggests where it is)",
			hash, nektonDir())
	}
	if len(trusted) == 0 {
		// Without a trust policy this LISTS and dereferences nothing. Opening a URI a stranger
		// named is a request made from this host and, for file://, a read of this host's disk -
		// neither is undone by the hash check that follows (AUD-03).
		fmt.Printf("%s: %d located-at claim(s), NONE verified - nothing dereferenced\n", hash, len(locs))
		for i, l := range locs {
			fmt.Printf("  [%d] %s  (self-asserted by=%q, signature UNVERIFIED)\n", i+1, l.uri, l.by)
		}
		return fmt.Errorf("refusing to dereference an unverified locator: pass --trust-keys <dir> naming the signers whose locations you accept")
	}
	var verified []location
	for _, l := range locs {
		if l.signer != "" {
			verified = append(verified, l)
		}
	}
	fmt.Printf("%s: %d located-at claim(s), %d signed by a trusted key\n", hash, len(locs), len(verified))
	if len(verified) == 0 {
		return fmt.Errorf("no located-at claim for %s verifies against --trust-keys", hash)
	}
	locs = verified

	bs, err := blobstore.OpenFor(planktonDir())
	if err != nil {
		return err
	}
	for i, l := range locs {
		// The keyid printed is the VERIFYING key's, never the envelope's declared one (§8).
		fmt.Printf("  [%d] %s  (verified signer key:%s) ... ", i+1, l.uri, l.signer)
		b, err := deref(l.uri, allowLocal)
		if err != nil {
			fmt.Printf("unreachable: %v\n", err)
			continue
		}
		if got := core.HashBytes(b); got != hash {
			fmt.Printf("HASH MISMATCH (got %s) - rejected\n", got)
			continue
		}
		if err := bs.PutVerified(hash, b); err != nil {
			return err
		}
		fmt.Printf("OK - %d bytes, verified & pinned\n", len(b))
		return nil
	}
	return fmt.Errorf("no suggested location resolved to bytes matching %s", hash)
}

// normalizeHash canonicalizes a content-hash argument so equivalent spellings compare equal: trims
// surrounding whitespace, adds the implicit "sha256:" for a bare hex digest, and lowercases (hex is
// lowercase by convention). Without this, an authentic blob given as bare hex, UPPERCASE hex, or with a
// stray newline read as CORRUPT / MISMATCH / absent.
func normalizeHash(h string) string {
	h = strings.TrimSpace(h)
	if !strings.Contains(h, ":") {
		h = "sha256:" + h
	}
	return strings.ToLower(h)
}

// location is a suggestion, and `signer` is what makes it more than that: it is the keyid of a key
// that ACTUALLY VERIFIED this claim, not the envelope's declared keyid (SPEC §8 - that field is not
// covered by the signature and any relabeler can set it to a victim's). Empty means unverified, and
// an unverified locator is never dereferenced.
type location struct{ uri, by, signer string }

// locatedAt collects the signed location suggestions for `hash`: located-at claims whose
// subject is that hash. kton recognizes the located-at predicate as a convention and reads
// nothing else into it.
func locatedAt(r *nreg.Registry, hash string, trusted []ed25519.PublicKey) []location {
	var out []location
	for _, rec := range r.About(hash) {
		st, _, err := claim.ParseEnvelope(rec.Envelope)
		if err != nil {
			continue
		}
		// Ingest stores signed claims WITHOUT verifying them (SPEC §8: the wire carries a keyid, not
		// a key), so "it is in the registry" says nothing about who put it there. Anyone able to put
		// a claim in front of this registry could otherwise choose the URI this process opens.
		signer := core.VerifiedSignerKeyID(rec.Envelope, trusted)
		var body map[string]any
		if err := json.Unmarshal(st.Predicate, &body); err != nil {
			continue
		}
		if predURI(body) != LocatedAtTerm {
			continue
		}
		obj, _ := body["object"].(map[string]any)
		uri, _ := obj["uri"].(string)
		if uri == "" {
			continue
		}
		by, _ := body["by"].(string)
		out = append(out, location{uri: uri, by: by, signer: signer})
	}
	return out
}

func predURI(body map[string]any) string {
	if p, ok := body["predicate"].(map[string]any); ok {
		if u, ok := p["uri"].(string); ok {
			return u
		}
	}
	return ""
}

// deref dereferences a URI to bytes. Resolver backends live ONLY here in the cockpit; http(s)
// and file today, git/ipfs are future kton backends. The kernels never do this.
// maxDeref bounds a fetched body. A locator names a size nobody here chose, and "verify the hash
// afterwards" does not help if the read never finishes.
const maxDeref = 512 << 20

func deref(uri string, allowLocal bool) ([]byte, error) {
	switch {
	case strings.HasPrefix(uri, "http://"), strings.HasPrefix(uri, "https://"):
		c := &http.Client{
			Timeout: 120 * time.Second,
			// THE address check happens in the dialer, not here: see guardedDial. Checking a
			// hostname and then handing the URL to a client that resolves it AGAIN means the
			// address checked is not the address contacted, and a resolver that answers
			// differently the second time walks straight through (dev review R01).
			Transport: &http.Transport{
				DialContext:           guardedDial(allowLocal),
				TLSHandshakeTimeout:   30 * time.Second,
				ResponseHeaderTimeout: 60 * time.Second,
			},
			// A redirect is a SECOND destination the locator did not name. The dialer checks it
			// too - this is the early, friendlier refusal, and a bound on redirect depth.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects")
				}
				return checkDestination(req.URL.Hostname(), allowLocal)
			},
		}
		u, err := url.Parse(uri)
		if err != nil {
			return nil, err
		}
		if err := checkDestination(u.Hostname(), allowLocal); err != nil {
			return nil, err
		}
		resp, err := c.Get(uri)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, maxDeref))
	case strings.HasPrefix(uri, "file://"):
		// A local path is not a location a stranger gets to name. Even a VERIFIED signer is naming
		// a path on THIS machine, which their signature says nothing about - so this needs a second,
		// explicit yes from the operator (--allow-local).
		if !allowLocal {
			return nil, fmt.Errorf("refusing a file:// locator: it names a path on THIS host, which a signature about content cannot vouch for; pass --allow-local if you meant it")
		}
		f, err := os.Open(strings.TrimPrefix(uri, "file://"))
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return io.ReadAll(io.LimitReader(f, maxDeref))
	default:
		return nil, fmt.Errorf("no kton resolver for the scheme of %q", uri)
	}
}

// checkDestination refuses the addresses a locator should never be able to reach from this host:
// loopback, link-local (the cloud metadata service lives at 169.254.169.254), private ranges and
// the unspecified address. A hash check afterwards proves what the bytes ARE; it says nothing about
// the request having been made, and the request is the exploit here.
func checkDestination(host string, allowLocal bool) error {
	if allowLocal {
		return nil
	}
	if host == "" {
		return fmt.Errorf("locator has no host")
	}
	ips, err := lookupIP(host)
	if err != nil {
		return fmt.Errorf("cannot resolve %q: %w", host, err)
	}
	return checkIPs(ips)
}

// checkIPs is the policy itself, over addresses rather than a name. Separated from the lookup so
// that the DIALER can apply it to the addresses it is about to connect to - which is the only place
// the check is load-bearing.
func checkIPs(ips []net.IP) error {
	for _, ip := range ips {
		switch {
		case ip.IsLoopback():
			return fmt.Errorf("refusing a locator pointing at loopback (%s); pass --allow-local if you meant it", ip)
		case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
			return fmt.Errorf("refusing a locator pointing at a link-local address (%s) - this is where cloud metadata services live", ip)
		case ip.IsPrivate():
			return fmt.Errorf("refusing a locator pointing into a private range (%s); pass --allow-local if you meant it", ip)
		case ip.IsUnspecified():
			return fmt.Errorf("refusing a locator pointing at the unspecified address")
		}
	}
	return nil
}

// lookupIP is net.LookupIP behind a variable so a test can answer differently on each call - which
// is precisely the attack: a resolver that returns a public address to the check and a loopback
// address to the connection.
var lookupIP = net.LookupIP

// guardedDial closes the gap between the address CHECKED and the address CONNECTED TO.
//
// The old path called checkDestination(hostname) and then handed the URL to an http.Client whose
// transport resolved that hostname again. Two lookups, and nothing tied them together: a resolver
// under the attacker's control (or a TTL-0 record) answers 93.184.216.34 to the first and 127.0.0.1
// to the second, and `--allow-local` is bypassed without ever being passed. That is DNS rebinding,
// and a hash check afterwards does not help - the request has already been made, and making the
// request IS the exploit against a metadata service or an internal host.
//
// Here the name is resolved ONCE, every address it returns is checked, and the connection is then
// made to a checked address as an IP LITERAL. There is no second lookup for a second answer to come
// back from. TLS still verifies against the URL's hostname: net/http sets the ServerName from the
// request, not from what the dialer connected to.
func guardedDial(allowLocal bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if ip := net.ParseIP(host); ip != nil {
			// Already a literal - nothing can change under us, but it still has to pass.
			if !allowLocal {
				if err := checkIPs([]net.IP{ip}); err != nil {
					return nil, err
				}
			}
			return d.DialContext(ctx, network, addr)
		}
		ips, err := lookupIP(host)
		if err != nil {
			return nil, fmt.Errorf("cannot resolve %q: %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("%q resolved to no addresses", host)
		}
		if !allowLocal {
			// ALL of them, not the one we happen to dial: a host answering with one public and one
			// loopback address is not a host this should talk to at all. Refusing outright also
			// keeps the refusal independent of which address the dial happens to succeed on.
			if err := checkIPs(ips); err != nil {
				return nil, err
			}
		}
		var lastErr error
		for _, ip := range ips {
			conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}

// loadTrustKeys reads a directory of *.pub keys. Mirrors plankton's loader deliberately: a consumer
// should be able to point both tools at the same directory and mean the same thing by it.
func loadTrustKeys(dir string) ([]ed25519.PublicKey, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var keys []ed25519.PublicKey
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pub") {
			continue
		}
		b, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			return nil, rerr
		}
		pub, perr := core.ParsePublicKeyHex(strings.TrimSpace(string(b)))
		if perr != nil {
			return nil, fmt.Errorf("trust-keys: %s: %w", e.Name(), perr)
		}
		keys = append(keys, pub)
	}
	return keys, nil
}
