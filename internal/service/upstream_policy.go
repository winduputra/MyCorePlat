package service

import (
	"fmt"
	"net"
)

// ErrUpstreamAddressNotAllowed is returned when a resolved address falls outside
// the permitted upstream address policy.
var ErrUpstreamAddressNotAllowed = fmt.Errorf("upstream address is not allowed")

// ErrUpstreamResolveFailed is returned when a hostname cannot be resolved into a
// usable set of addresses. Callers must treat it as a denial (fail closed).
var ErrUpstreamResolveFailed = fmt.Errorf("upstream hostname could not be resolved")

// defaultUpstreamCIDRs mirrors the approved Phase 0 policy: tool services run on
// private/internal networks only. Operators narrow this via configuration.
var defaultUpstreamCIDRs = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"fc00::/7", // IPv6 unique local addresses
}

// alwaysDeniedCIDRs are ranges that must never be reachable, even when an
// operator adds them to the allowed CIDR list: they are either not routable,
// reserved for documentation/benchmarks, or used for cloud metadata services.
var alwaysDeniedCIDRs = func() []*net.IPNet {
	entries := []string{
		"0.0.0.0/8",          // "this network"
		"100.64.0.0/10",      // carrier-grade NAT, also cloud metadata (100.100.100.200)
		"192.0.0.0/24",       // IETF protocol assignments
		"192.0.2.0/24",       // TEST-NET-1
		"198.18.0.0/15",      // benchmarking
		"198.51.100.0/24",    // TEST-NET-2
		"203.0.113.0/24",     // TEST-NET-3
		"240.0.0.0/4",        // reserved
		"255.255.255.255/32", // limited broadcast
		"::/128",             // unspecified
		"::1/128",            // loopback
		"fe80::/10",          // link-local
		"fec0::/10",          // deprecated site-local
		"ff00::/8",           // multicast
		"2001:db8::/32",      // documentation
		"64:ff9b::/96",       // NAT64
		"fd00:ec2::254/128",  // AWS IMDSv6
	}
	nets := make([]*net.IPNet, 0, len(entries))
	for _, entry := range entries {
		_, ipNet, err := net.ParseCIDR(entry)
		if err != nil {
			panic("service: invalid always-denied CIDR " + entry)
		}
		nets = append(nets, ipNet)
	}
	return nets
}()

// UpstreamIPPolicy decides which IP addresses Core may connect to for a tool
// upstream. The zero value is unusable; construct one with
// DefaultUpstreamIPPolicy or NewUpstreamIPPolicy. Addresses are permitted only
// when they are inside the configured CIDR set AND are not a denied class
// (loopback, link-local, multicast, unspecified, reserved, cloud metadata).
type UpstreamIPPolicy struct {
	allowed        []*net.IPNet
	permitLoopback bool
	set            bool
}

// DefaultUpstreamIPPolicy returns the approved Phase 0 policy: private/internal
// ranges only.
func DefaultUpstreamIPPolicy() UpstreamIPPolicy {
	policy, err := NewUpstreamIPPolicy(defaultUpstreamCIDRs)
	if err != nil {
		// The defaults are compile-time constants; a failure is a programming bug.
		panic("service: invalid default upstream CIDRs: " + err.Error())
	}
	return policy
}

// NewUpstreamIPPolicy parses the operator-supplied CIDR allowlist. It rejects an
// empty list (default deny must be explicit) and malformed entries. The CIDR
// list is sourced from server-side configuration only, never from a client
// request or a tool manifest.
func NewUpstreamIPPolicy(cidrs []string) (UpstreamIPPolicy, error) {
	if len(cidrs) == 0 {
		return UpstreamIPPolicy{}, fmt.Errorf("upstream CIDR allowlist is empty")
	}
	allowed := make([]*net.IPNet, 0, len(cidrs))
	for _, entry := range cidrs {
		_, ipNet, err := net.ParseCIDR(entry)
		if err != nil {
			return UpstreamIPPolicy{}, fmt.Errorf("invalid upstream CIDR %q: %w", entry, err)
		}
		allowed = append(allowed, ipNet)
	}
	return UpstreamIPPolicy{allowed: allowed, set: true}, nil
}

// NewLoopbackUpstreamPolicyForTests builds a policy that additionally permits
// loopback addresses. It exists only so tests can proxy to httptest servers on
// 127.0.0.1; production code must never use it.
func NewLoopbackUpstreamPolicyForTests() UpstreamIPPolicy {
	base := append([]string{}, defaultUpstreamCIDRs...)
	base = append(base, "127.0.0.0/8", "::1/128")
	policy, err := NewUpstreamIPPolicy(base)
	if err != nil {
		panic("service: invalid test upstream CIDRs: " + err.Error())
	}
	policy.permitLoopback = true
	return policy
}

// IsConfigured reports whether the policy was constructed. An unconfigured policy
// denies everything, so callers must not silently skip validation.
func (p UpstreamIPPolicy) IsConfigured() bool { return p.set }

// Permits reports whether Core may connect to ip. It returns a descriptive error
// (wrapped ErrUpstreamAddressNotAllowed) when the address is denied.
func (p UpstreamIPPolicy) Permits(ip net.IP) error {
	if ip == nil {
		return fmt.Errorf("%w: missing address", ErrUpstreamAddressNotAllowed)
	}

	// IPv4-mapped IPv6 (::ffff:a.b.c.d) is normalized to its IPv4 form so that
	// every policy check applies to the address the kernel will actually use.
	var candidate net.IP
	if v4 := ip.To4(); v4 != nil {
		candidate = v4
	} else {
		candidate = ip
	}

	if err := denyClass(candidate, p.permitLoopback); err != nil {
		return err
	}

	if !p.set {
		return fmt.Errorf("%w: %s denied (no upstream address policy configured)", ErrUpstreamAddressNotAllowed, candidate)
	}

	for _, ipNet := range p.allowed {
		if ipNet.Contains(candidate) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s is outside the allowed upstream CIDRs", ErrUpstreamAddressNotAllowed, candidate)
}

// denyClass rejects address classes that must never be an upstream target.
func denyClass(ip net.IP, permitLoopback bool) error {
	if ip.IsLoopback() {
		if !permitLoopback {
			return fmt.Errorf("%w: %s is a loopback address", ErrUpstreamAddressNotAllowed, ip)
		}
		// Test-only policy: loopback is the target, nothing further to deny.
		return nil
	}
	switch {
	case ip.IsLinkLocalUnicast(),
		ip.IsLinkLocalMulticast(),
		ip.IsInterfaceLocalMulticast(),
		ip.IsMulticast(),
		ip.IsUnspecified():
		return fmt.Errorf("%w: %s is a link-local/multicast/unspecified address", ErrUpstreamAddressNotAllowed, ip)
	}
	for _, denied := range alwaysDeniedCIDRs {
		if denied.Contains(ip) {
			return fmt.Errorf("%w: %s is a reserved or metadata address", ErrUpstreamAddressNotAllowed, ip)
		}
	}
	return nil
}
