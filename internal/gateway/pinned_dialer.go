package gateway

import (
	"context"
	"fmt"
	"net"

	"github.com/winduputra/MyCorePlat/internal/service"
)

// pinnedDialer resolves and validates a hostname once per connection and then
// dials the validated address.
//
// This is what defeats DNS rebinding: the address that was validated is the
// exact address dialed, so a name that resolves differently on a second lookup
// cannot redirect the connection. The original hostname is never resolved again
// here, and there is no fallback to an unvalidated system lookup — if resolution
// or validation fails, the connection fails.
//
// TLS SNI and the HTTP Host header are unaffected: the transport still uses the
// hostname from the request URL for both, so certificates keep being validated
// against the name the operator configured.
type pinnedDialer struct {
	resolver service.IPResolver
	policy   service.UpstreamIPPolicy
	allow    service.UpstreamAllowlist
	dialer   *net.Dialer
}

func (d *pinnedDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("gateway: invalid upstream address %q", addr)
	}
	if host == "" || port == "" {
		return nil, fmt.Errorf("gateway: invalid upstream address %q", addr)
	}

	// Hostnames must still be on the configured allowlist; IP literals are
	// validated by the address policy below instead.
	if net.ParseIP(host) == nil && !d.allow.Contains(host) {
		return nil, fmt.Errorf("%w: host %q is not in the allowed upstream list", service.ErrInvalidUpstream, host)
	}

	addresses, err := service.ResolveAllowedUpstream(ctx, d.resolver, host, d.policy)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for _, ip := range addresses {
		conn, dialErr := d.dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	if lastErr == nil {
		// Unreachable: ResolveAllowedUpstream never returns an empty set.
		lastErr = service.ErrUpstreamResolveFailed
	}
	return nil, lastErr
}
