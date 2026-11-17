package service

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// requestFrom builds a request whose TCP peer is remoteAddr and whose
// X-Forwarded-For header (if forwardedFor is non-empty) simulates a chain of
// proxies that appended their client addresses.
func requestFrom(remoteAddr, forwardedFor string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remoteAddr
	if forwardedFor != "" {
		r.Header.Set("X-Forwarded-For", forwardedFor)
	}
	return r
}

func mustResolver(t *testing.T, trusted ...string) *ClientIPResolver {
	t.Helper()
	resolver, err := NewClientIPResolver(trusted)
	if err != nil {
		t.Fatalf("NewClientIPResolver(%v): %v", trusted, err)
	}
	return resolver
}

// TestNoTrustedProxiesIgnoresForwardedHeader is the safe default: when nothing
// is trusted, X-Forwarded-For must be ignored entirely so a direct client
// cannot choose its own address.
func TestNoTrustedProxiesIgnoresForwardedHeader(t *testing.T) {
	resolver := mustResolver(t)

	got := resolver.Resolve(requestFrom("203.0.113.40:5555", "1.2.3.4"))
	if got != "203.0.113.40" {
		t.Fatalf("Resolve = %q, want the peer address 203.0.113.40 (header must be ignored)", got)
	}
}

// TestZeroValueResolverIsSafe ensures a nil/zero resolver behaves like "trust
// nothing" rather than panicking.
func TestZeroValueResolverIsSafe(t *testing.T) {
	var resolver *ClientIPResolver
	if got := resolver.Resolve(requestFrom("198.51.100.7:1234", "9.9.9.9")); got != "198.51.100.7" {
		t.Fatalf("nil resolver Resolve = %q, want peer address", got)
	}
}

// TestTrustedProxyUsesForwardedClient covers the normal single-proxy deployment:
// NPM at 172.18.0.3 forwards a request from a real client.
func TestTrustedProxyUsesForwardedClient(t *testing.T) {
	resolver := mustResolver(t, "172.18.0.3")

	got := resolver.Resolve(requestFrom("172.18.0.3:40212", "36.72.11.9"))
	if got != "36.72.11.9" {
		t.Fatalf("Resolve = %q, want the forwarded client 36.72.11.9", got)
	}
}

// TestUntrustedProxyHeaderIsIgnored asserts that a request arriving from an
// address that is NOT a trusted proxy cannot inject a client address.
func TestUntrustedProxyHeaderIsIgnored(t *testing.T) {
	resolver := mustResolver(t, "172.18.0.3")

	got := resolver.Resolve(requestFrom("45.33.10.20:5555", "1.2.3.4"))
	if got != "45.33.10.20" {
		t.Fatalf("Resolve = %q, want the untrusted peer 45.33.10.20", got)
	}
}

// TestSpoofedForwardedForFromDirectClientCannotEscape is the core anti-spoof
// guarantee: a direct client sending its own X-Forwarded-For header is not a
// trusted proxy, so the header is discarded and the real peer is used.
func TestSpoofedForwardedForFromDirectClientCannotEscape(t *testing.T) {
	resolver := mustResolver(t, "172.18.0.3")

	for _, spoof := range []string{"1.1.1.1", "8.8.8.8, 1.1.1.1", " 9.9.9.9 , 10.0.0.1 "} {
		got := resolver.Resolve(requestFrom("45.33.10.20:5555", spoof))
		if got != "45.33.10.20" {
			t.Fatalf("spoofed XFF %q yielded %q, want the peer 45.33.10.20", spoof, got)
		}
	}
}

// TestClientCannotPrependSpoofedHopBehindTrustedProxy models the classic bypass:
// a client appends its own X-Forwarded-For entry, then the trusted proxy appends
// the client's real address. Only the right-most untrusted hop may be used.
func TestClientCannotPrependSpoofedHopBehindTrustedProxy(t *testing.T) {
	resolver := mustResolver(t, "172.18.0.3")

	// The client sent "X-Forwarded-For: 1.2.3.4" itself; NPM then appended the
	// real client address 36.72.11.9, producing "1.2.3.4, 36.72.11.9".
	got := resolver.Resolve(requestFrom("172.18.0.3:40212", "1.2.3.4, 36.72.11.9"))
	if got != "36.72.11.9" {
		t.Fatalf("Resolve = %q, want the real client 36.72.11.9 (right-most untrusted hop)", got)
	}
}

// TestMultiHopChainSkipsTrustedProxies covers a CDN -> NPM -> Core chain where
// both upstream hops are trusted.
func TestMultiHopChainSkipsTrustedProxies(t *testing.T) {
	resolver := mustResolver(t, "172.18.0.3", "10.0.0.2")

	// CDN 10.0.0.2 saw the client, NPM 172.18.0.3 appended the CDN address.
	got := resolver.Resolve(requestFrom("172.18.0.3:40212", "36.72.11.9, 10.0.0.2"))
	if got != "36.72.11.9" {
		t.Fatalf("Resolve = %q, want the client 36.72.11.9 behind two trusted hops", got)
	}
}

// TestAllTrustedHopsReturnsLeftmost handles a chain made only of trusted
// proxies (no client address recorded); the left-most entry is the best guess.
func TestAllTrustedHopsReturnsLeftmost(t *testing.T) {
	resolver := mustResolver(t, "172.18.0.3", "10.0.0.2")

	got := resolver.Resolve(requestFrom("172.18.0.3:40212", "10.0.0.2"))
	if got != "10.0.0.2" {
		t.Fatalf("Resolve = %q, want the left-most trusted hop 10.0.0.2", got)
	}
}

// TestTrustedCIDRAllowsMemberProxy supports an explicit trusted range (e.g. the
// Docker proxy network) while still ignoring unknown peers.
func TestTrustedCIDRAllowsMemberProxy(t *testing.T) {
	resolver := mustResolver(t, "172.18.0.0/16")

	member := resolver.Resolve(requestFrom("172.18.0.3:40212", "36.72.11.9"))
	if member != "36.72.11.9" {
		t.Fatalf("trusted CIDR member Resolve = %q, want 36.72.11.9", member)
	}
	outside := resolver.Resolve(requestFrom("192.0.2.5:40212", "36.72.11.9"))
	if outside != "192.0.2.5" {
		t.Fatalf("outside trusted CIDR Resolve = %q, want the peer 192.0.2.5", outside)
	}
}

// TestMalformedForwardedEntriesAreSkipped ensures junk hops never become the
// reported client.
func TestMalformedForwardedEntriesAreSkipped(t *testing.T) {
	resolver := mustResolver(t, "172.18.0.3")

	got := resolver.Resolve(requestFrom("172.18.0.3:40212", "unknown, , 36.72.11.9"))
	if got != "36.72.11.9" {
		t.Fatalf("Resolve = %q, want 36.72.11.9 after skipping malformed hops", got)
	}
}

// TestForwardedForWithoutPortAndWithPortBothParse accepts common proxy formats.
func TestForwardedForWithoutPortAndWithPortBothParse(t *testing.T) {
	resolver := mustResolver(t, "172.18.0.3")

	if got := resolver.Resolve(requestFrom("172.18.0.3:40212", "36.72.11.9")); got != "36.72.11.9" {
		t.Fatalf("no-port Resolve = %q", got)
	}
	if got := resolver.Resolve(requestFrom("172.18.0.3:40212", "36.72.11.9:51000")); got != "36.72.11.9" {
		t.Fatalf("with-port Resolve = %q", got)
	}
}

// TestIPv6ClientAddressIsPreserved checks bracketed IPv6 parsing.
func TestIPv6ClientAddressIsPreserved(t *testing.T) {
	resolver := mustResolver(t, "172.18.0.3")

	got := resolver.Resolve(requestFrom("172.18.0.3:40212", "2001:db8::5"))
	if got != "2001:db8::5" {
		t.Fatalf("Resolve = %q, want 2001:db8::5", got)
	}
}

// TestNoForwardedHeaderFromTrustedProxyFallsBackToPeer covers a trusted proxy
// that forgot to set the header; the peer address is still the best answer.
func TestNoForwardedHeaderFromTrustedProxyFallsBackToPeer(t *testing.T) {
	resolver := mustResolver(t, "172.18.0.3")

	got := resolver.Resolve(requestFrom("172.18.0.3:40212", ""))
	if got != "172.18.0.3" {
		t.Fatalf("Resolve = %q, want the trusted peer 172.18.0.3", got)
	}
}

// TestNewClientIPResolverRejectsInvalidEntry fails fast on a typo'd config
// instead of silently trusting nothing (or, worse, everything).
func TestNewClientIPResolverRejectsInvalidEntry(t *testing.T) {
	for _, bad := range []string{"not-an-ip", "172.18.0.0/33", "172.18.0.3/", ""} {
		if _, err := NewClientIPResolver([]string{bad}); err == nil {
			t.Fatalf("NewClientIPResolver(%q) = nil error, want an error", bad)
		}
	}
}

// TestClientIPResolverIsConcurrencySafe exercises the resolver from many
// goroutines to confirm it holds no mutable shared state.
func TestClientIPResolverIsConcurrencySafe(t *testing.T) {
	resolver := mustResolver(t, "172.18.0.3")

	done := make(chan struct{})
	for i := 0; i < 32; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			if got := resolver.Resolve(requestFrom("172.18.0.3:40212", "36.72.11.9")); got != "36.72.11.9" {
				t.Errorf("concurrent Resolve = %q", got)
			}
		}()
	}
	for i := 0; i < 32; i++ {
		<-done
	}
}
