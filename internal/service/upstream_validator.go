package service

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// ErrInvalidUpstream is returned when an upstream URL fails SSRF validation.
var ErrInvalidUpstream = fmt.Errorf("invalid upstream url")

// allowedPorts is the set of ports a tool upstream may use. Keeping this narrow
// prevents an admin/manifest from pointing Core at unrelated internal services
// (databases, caches, SSH, etc.).
var allowedPorts = map[string]bool{
	"":     true, // scheme default
	"80":   true,
	"443":  true,
	"3000": true,
	"5000": true,
	"8000": true,
	"8080": true,
	"8443": true,
	"9000": true,
}

// UpstreamAllowlist is the set of hostnames Core is permitted to proxy to. It is
// the authoritative allowlist and MUST be sourced from server-side
// configuration only — never from client input or a tool manifest. A hostname
// not present here is rejected (default deny).
type UpstreamAllowlist map[string]bool

// NewUpstreamAllowlist builds an allowlist from configured host entries. Entries
// are normalized (lowercased, trailing dot trimmed) and de-duplicated. Empty
// entries are ignored.
func NewUpstreamAllowlist(hosts ...string) UpstreamAllowlist {
	allow := make(UpstreamAllowlist, len(hosts))
	for _, h := range hosts {
		if normalized, ok := normalizeHostname(h); ok {
			allow[normalized] = true
		}
	}
	return allow
}

// Contains reports whether the (already normalized candidates also accepted)
// host is explicitly allowed.
func (a UpstreamAllowlist) Contains(host string) bool {
	if len(a) == 0 {
		return false
	}
	normalized, ok := normalizeHostname(host)
	if !ok {
		return false
	}
	if a[normalized] {
		return true
	}
	// Also match the original (pre-trailing-dot) form for robustness.
	return a[strings.ToLower(host)]
}

// hostnamePattern validates a hostname per RFC 1123 label rules: one or more
// dot-separated labels of letters/digits/hyphens, each label not starting or
// ending with a hyphen. Underscores are rejected because they are not valid in
// hostnames (Docker service names use hyphens).
var hostnamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// normalizeHostname lowercases the host, trims a single trailing dot, and
// validates it as a hostname. It returns the normalized host and whether it is
// a syntactically valid hostname.
func normalizeHostname(host string) (string, bool) {
	h := strings.ToLower(strings.TrimSpace(host))
	// A single trailing dot denotes the DNS root; treat it as equivalent.
	h = strings.TrimSuffix(h, ".")
	if h == "" || len(h) > 253 {
		return "", false
	}
	if !hostnamePattern.MatchString(h) {
		return "", false
	}
	return h, true
}

// reservedHostnames are names that must never be reachable even if an operator
// mistakenly adds them to the allowlist: loopback aliases and cloud metadata
// endpoints are classic SSRF targets.
var reservedHostnames = map[string]bool{
	"localhost":                true,
	"ip6-localhost":            true,
	"ip6-loopback":             true,
	"metadata":                 true,
	"metadata.google.internal": true,
}

// isReservedHostname reports whether host (already normalized) is a reserved
// name that must always be denied regardless of allowlist membership.
func isReservedHostname(host string) bool {
	if reservedHostnames[host] {
		return true
	}
	return strings.HasSuffix(host, ".localhost")
}

// nonStandardIPPattern matches numeric host forms that some resolvers interpret
// as IP addresses (decimal, octal, or hex). Go's resolver rejects these, but we
// reject them explicitly as defense-in-depth so they can never be treated as an
// allowlisted hostname.
var nonStandardIPPattern = regexp.MustCompile(`^(0x[0-9a-f]+|[0-9]+)(\.(0x[0-9a-f]+|[0-9]+))*$`)

// ValidateUpstream enforces the upstream SSRF policy:
//   - scheme must be http or https;
//   - no userinfo;
//   - port must be in the port allowlist;
//   - IP-literal hosts must be private/internal (public, loopback, link-local,
//     unspecified and IPv4-mapped-public forms are rejected);
//   - hostname hosts must be present on the exact allowlist (default deny).
//
// It performs syntactic validation only. DNS-rebinding protection (connecting to
// the exact validated IP) and re-validation before each connection are deferred
// to the gateway; this function is the single entry point used on create/update
// and on manifest import.
func ValidateUpstream(raw string, allow UpstreamAllowlist) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("%w: empty", ErrInvalidUpstream)
	}

	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: parse: %v", ErrInvalidUpstream, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: scheme %q not allowed", ErrInvalidUpstream, u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("%w: userinfo not allowed", ErrInvalidUpstream)
	}
	if u.Host == "" {
		return fmt.Errorf("%w: missing host", ErrInvalidUpstream)
	}
	if !allowedPorts[u.Port()] {
		return fmt.Errorf("%w: port %q not allowed", ErrInvalidUpstream, u.Port())
	}

	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("%w: missing host", ErrInvalidUpstream)
	}

	// IP-literal path: validate the address directly, no allowlist needed.
	if ip := net.ParseIP(host); ip != nil {
		if isBlockedIP(ip) {
			return fmt.Errorf("%w: IP %q not allowed", ErrInvalidUpstream, host)
		}
		if !isPrivateIP(ip) {
			return fmt.Errorf("%w: IP %q is not internal", ErrInvalidUpstream, host)
		}
		return nil
	}

	// Reject non-standard numeric IP forms before hostname handling.
	if nonStandardIPPattern.MatchString(host) {
		return fmt.Errorf("%w: host %q is not a permitted form", ErrInvalidUpstream, host)
	}

	// Hostname path: must be a valid hostname, must not be a reserved name, and
	// must be present on the exact allowlist (default deny).
	normalized, ok := normalizeHostname(host)
	if !ok {
		return fmt.Errorf("%w: host %q is not a valid hostname", ErrInvalidUpstream, host)
	}
	if isReservedHostname(normalized) {
		return fmt.Errorf("%w: host %q is reserved", ErrInvalidUpstream, host)
	}
	if !allow.Contains(normalized) {
		return fmt.Errorf("%w: host %q is not in the allowed upstream list", ErrInvalidUpstream, host)
	}
	return nil
}

// isBlockedIP reports whether ip must never be a tool upstream (loopback,
// link-local, unspecified, multicast).
func isBlockedIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return true
	}
	return false
}

// isPrivateIP reports whether ip is within a private/internal range (RFC1918
// IPv4 or IPv6 unique-local/ULA).
func isPrivateIP(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 10:
			return true
		case v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31:
			return true
		case v4[0] == 192 && v4[1] == 168:
			return true
		default:
			return false
		}
	}
	// IPv6 unique local addresses: fc00::/7.
	if len(ip) == net.IPv6len && (ip[0]&0xfe) == 0xfc {
		return true
	}
	return false
}
