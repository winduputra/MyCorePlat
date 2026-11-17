package service

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// IPResolver resolves a hostname to every address it currently maps to. The
// gateway uses it so that DNS is consulted once, through a controlled resolver,
// and every answer is validated before any connection is attempted.
type IPResolver interface {
	LookupIP(ctx context.Context, host string) ([]net.IP, error)
}

// systemResolver resolves through the platform resolver (Docker's embedded DNS
// inside the container). It is the production resolver.
type systemResolver struct{}

func (systemResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	return addrs, nil
}

// SystemResolver returns the production resolver.
func SystemResolver() IPResolver { return systemResolver{} }

// ResolveAllowedUpstream resolves host and returns only addresses that the
// policy permits.
//
// Contract:
//   - an IP literal host is validated directly and never resolved;
//   - every address a hostname resolves to is validated — if ANY of them is
//     denied, the whole hostname is denied;
//   - a resolution failure or an empty answer is a denial (fail closed);
//   - IPv4-mapped IPv6 answers are normalized to IPv4.
//
// It never falls back to a second, unvalidated lookup: the caller dials the
// returned addresses.
func ResolveAllowedUpstream(ctx context.Context, resolver IPResolver, host string, policy UpstreamIPPolicy) ([]net.IP, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, fmt.Errorf("%w: empty host", ErrUpstreamResolveFailed)
	}

	if ip := net.ParseIP(host); ip != nil {
		if err := policy.Permits(ip); err != nil {
			return nil, err
		}
		return []net.IP{normalizeDialIP(ip)}, nil
	}

	if resolver == nil {
		return nil, fmt.Errorf("%w: no resolver configured", ErrUpstreamResolveFailed)
	}

	answers, err := resolver.LookupIP(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("%w: lookup %q: %v", ErrUpstreamResolveFailed, host, err)
	}
	if len(answers) == 0 {
		return nil, fmt.Errorf("%w: %q returned no addresses", ErrUpstreamResolveFailed, host)
	}

	validated := make([]net.IP, 0, len(answers))
	seen := make(map[string]bool, len(answers))
	for _, answer := range answers {
		if err := policy.Permits(answer); err != nil {
			// One forbidden address is enough to deny the hostname: accepting it
			// would make the connection target depend on resolver ordering.
			return nil, fmt.Errorf("%w: host %q resolves to a denied address: %v", ErrUpstreamAddressNotAllowed, host, err)
		}
		normalized := normalizeDialIP(answer)
		key := normalized.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		validated = append(validated, normalized)
	}
	return validated, nil
}

// normalizeDialIP converts IPv4-mapped IPv6 addresses to the plain IPv4 form so
// dialing produces the same target the policy validated.
func normalizeDialIP(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}
