package service

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// ClientIPResolver derives the real client address for a request that may have
// traversed one or more reverse proxies.
//
// Security model: by default nothing is trusted and the TCP peer address
// (RemoteAddr) is returned, so a direct client cannot forge its address through
// forwarding headers. Only when the immediate peer is a configured trusted
// proxy are forwarding headers consulted, and even then the chain is walked
// right-to-left so a client cannot prepend a fake hop: the first address that
// is not itself a trusted proxy is reported as the client.
//
// The trusted set comes exclusively from server-side configuration; it is never
// taken from the request. An empty set therefore means "trust no one", which is
// the safe default that preserves the pre-existing behaviour.
type ClientIPResolver struct {
	trusted []*net.IPNet
}

// NewClientIPResolver builds a resolver from a list of exact IP addresses or
// CIDR ranges. Each entry must parse; an invalid entry is a fail-fast error so a
// typo cannot silently widen or narrow what is trusted. An empty list yields a
// resolver that ignores all forwarding headers.
func NewClientIPResolver(trusted []string) (*ClientIPResolver, error) {
	resolver := &ClientIPResolver{}
	for _, entry := range trusted {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			return nil, fmt.Errorf("trusted proxy entry must not be blank")
		}
		// Accept either a bare IP (host) or an explicit CIDR range.
		if ip := net.ParseIP(entry); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			resolver.trusted = append(resolver.trusted, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy %q: %w", entry, err)
		}
		resolver.trusted = append(resolver.trusted, network)
	}
	return resolver, nil
}

// Resolve returns the client address for r.
//
// It returns the TCP peer address unless that peer is a trusted proxy, in which
// case the right-most untrusted address in X-Forwarded-For (falling back to the
// peer) is returned.
func (r *ClientIPResolver) Resolve(req *http.Request) string {
	peer := remoteHost(req.RemoteAddr)
	if r == nil || len(r.trusted) == 0 || !r.isTrusted(peer) {
		// Peer is not a trusted proxy: never look at client-supplied headers.
		return peer
	}

	hops := parseForwardedFor(req.Header.Get("X-Forwarded-For"))
	// Walk from the closest proxy outward, skipping trusted hops, and return
	// the first address that is not itself a trusted proxy: that is the client.
	for i := len(hops) - 1; i >= 0; i-- {
		if !r.isTrusted(hops[i]) {
			return hops[i]
		}
	}
	if len(hops) > 0 {
		// Every recorded hop is a trusted proxy (no client address captured);
		// the left-most entry is the best available answer.
		return hops[0]
	}
	return peer
}

// isTrusted reports whether addr (a bare IP string) falls in the trusted set.
func (r *ClientIPResolver) isTrusted(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	for _, network := range r.trusted {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// remoteHost extracts the host portion of a RemoteAddr ("ip:port"). Bare
// addresses without a port are returned unchanged.
func remoteHost(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		if host != "" {
			return host
		}
	}
	return remoteAddr
}

// parseForwardedFor splits an X-Forwarded-For value into individual hop
// addresses, trimming whitespace, dropping empty and malformed entries, and
// stripping any port so only the address remains.
func parseForwardedFor(raw string) []string {
	if raw == "" {
		return nil
	}
	hops := make([]string, 0, 4)
	for _, part := range strings.Split(raw, ",") {
		hop := strings.TrimSpace(part)
		if hop == "" {
			continue
		}
		// Accept "ip" or "ip:port" (and "[ipv6]:port").
		if host, _, err := net.SplitHostPort(hop); err == nil {
			hop = host
		}
		if net.ParseIP(hop) == nil {
			continue
		}
		hops = append(hops, hop)
	}
	return hops
}
