package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

// R01: checkDestination resolved the hostname, then the http.Client resolved it AGAIN. Two lookups,
// nothing tying them together - so a resolver that answers a public address to the check and a
// loopback address to the connection bypassed --allow-local without it ever being passed. The hash
// check afterwards does not help: the request has already been made, and making the request is the
// exploit against a metadata service or an internal host.
//
// The test is the attack: a resolver whose FIRST answer is public and whose every later answer is
// loopback, in front of a real loopback server holding content only a local caller could see.
func TestFetchDoesNotFollowADNSRebind(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "local-only response")
	}))
	defer srv.Close()
	srvURL, _ := url.Parse(srv.URL)
	loopback := net.ParseIP(srvURL.Hostname())
	if loopback == nil || !loopback.IsLoopback() {
		t.Fatalf("test server is not on loopback: %s", srv.URL)
	}

	var lookups int32
	realLookup := lookupIP
	defer func() { lookupIP = realLookup }()
	lookupIP = func(host string) ([]net.IP, error) {
		if strings.EqualFold(host, "rebind.invalid") {
			if atomic.AddInt32(&lookups, 1) == 1 {
				return []net.IP{net.ParseIP("93.184.216.34")}, nil // public: passes the check
			}
			return []net.IP{loopback}, nil // every later answer: the real target
		}
		return realLookup(host)
	}

	// checkDestination is left on the real resolver on purpose - the point is that even when the
	// NAME check passes, the connection must not reach loopback.
	body, err := deref("http://rebind.invalid:"+srvURL.Port()+"/x", false)
	if err == nil {
		t.Fatalf("deref followed a rebind and returned %q with allowLocal=false", string(body))
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Errorf("refused, but not for the right reason: %v", err)
	}
	// TWO lookups is the whole point: the name check took the first answer (public, so it passed)
	// and the DIALER took the second (loopback, so it refused). One lookup would mean the dialer
	// never applied the policy itself and the refusal came only from the name check - which is the
	// arrangement that was vulnerable.
	if got := atomic.LoadInt32(&lookups); got < 2 {
		t.Errorf("the guarded dialer did not resolve and check at dial time (lookups=%d, want >=2)", got)
	}
}

// What this test can and cannot show. It proves the policy is applied where the CONNECTION is made,
// on the answer the resolver gives at that moment. It does not carry out a real rebind: the old,
// unguarded transport used the system resolver, which this seam cannot reach, so against that code
// the test fails by never consulting the seam rather than by reaching the loopback server. The
// exploit itself needs real DNS under the attacker's control; what is testable here is whether the
// address checked is the address dialled, and that is what changed.

// The guard must not break the ordinary case, and must still refuse a plain literal.
func TestGuardedDialPolicy(t *testing.T) {
	dial := guardedDial(false)
	for _, addr := range []string{"127.0.0.1:80", "169.254.169.254:80", "10.0.0.1:80", "0.0.0.0:80"} {
		if _, err := dial(context.Background(), "tcp", addr); err == nil {
			t.Errorf("guarded dial accepted %s", addr)
		}
	}
	// With --allow-local the operator has said yes; the dialer must not second-guess that.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	c, err := guardedDial(true)(context.Background(), "tcp", net.JoinHostPort(u.Hostname(), u.Port()))
	if err != nil {
		t.Fatalf("--allow-local still refused loopback: %v", err)
	}
	c.Close()
}
