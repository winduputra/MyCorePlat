package service

import (
	"context"
	"fmt"
	"net"
)

// healthPinnedDialer dials only addresses that passed the Task 9 checks.
//
// It is a service-package twin of the gateway's pinned dialer: the health
// poller must not depend on the gateway package (which imports this one), and
// duplicating the small validation step is preferable to letting the poller
// use a plain dialer that skips the SSRF policy entirely.
type healthPinnedDialer struct {
	resolver IPResolver
	policy   UpstreamIPPolicy
	allow    UpstreamAllowlist
	dialer   *net.Dialer
}

// DialContext resolves the host, validates every answer, and dials the
// validated IP. TLS SNI and the Host header keep the original hostname because
// the transport rewrites them from the request URL.
func (d *healthPinnedDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("health: invalid probe address: %w", err)
	}
	if host == "" || port == "" {
		return nil, fmt.Errorf("health: incomplete probe address")
	}

	if net.ParseIP(host) == nil && !d.allow.Contains(host) {
		return nil, fmt.Errorf("%w: host %q is not in the allowed upstream list", ErrInvalidUpstream, host)
	}

	ips, err := ResolveAllowedUpstream(ctx, d.resolver, host, d.policy)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for _, ip := range ips {
		conn, dialErr := d.dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrUpstreamResolveFailed
}
