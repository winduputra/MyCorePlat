package service

import (
	"errors"
	"net"
	"testing"
)

// testAllowlist is the server-side allowlist used across tests. Only these
// hostnames may be used as upstreams.
func testAllowlist() UpstreamAllowlist {
	return NewUpstreamAllowlist("image-compressor", "image_compressor", "svc", "backend-api", "x")
}

func TestValidateUpstreamAcceptsAllowlistedHostname(t *testing.T) {
	allow := testAllowlist()
	cases := []string{
		"http://image-compressor:8000",
		"https://image-compressor:8443",
		"http://image-compressor",
		"http://image-compressor/health",
		"http://backend-api:8080",
	}
	for _, c := range cases {
		if err := ValidateUpstream(c, allow); err != nil {
			t.Errorf("ValidateUpstream(%q) error = %v, want nil", c, err)
		}
	}
}

func TestValidateUpstreamRejectsUnregisteredInternalHostname(t *testing.T) {
	allow := testAllowlist()
	// Syntactically valid service names that are simply not on the allowlist.
	for _, c := range []string{
		"http://some-other-service:8000",
		"http://totally-random-xyz:8000",
		"http://svc2:8000",
	} {
		if err := ValidateUpstream(c, allow); !errors.Is(err, ErrInvalidUpstream) {
			t.Errorf("ValidateUpstream(%q) error = %v, want ErrInvalidUpstream", c, err)
		}
	}
}

func TestValidateUpstreamRejectsAttackerHostnames(t *testing.T) {
	allow := testAllowlist()
	for _, c := range []string{
		"http://attacker.zz:8000",
		"http://attacker.zip:8000",
		"http://attacker.internal:8000",
		"http://attacker.com.local:8000",
		"http://evil.museum:8000",
		"http://example.com",
	} {
		if err := ValidateUpstream(c, allow); !errors.Is(err, ErrInvalidUpstream) {
			t.Errorf("ValidateUpstream(%q) error = %v, want ErrInvalidUpstream", c, err)
		}
	}
}

func TestValidateUpstreamNormalizesCaseAndTrailingDot(t *testing.T) {
	allow := testAllowlist()
	for _, c := range []string{
		"http://IMAGE-COMPRESSOR:8000",
		"http://Image-Compressor:8000",
		"http://image-compressor.:8000",
		"http://IMAGE-COMPRESSOR.:8000",
	} {
		if err := ValidateUpstream(c, allow); err != nil {
			t.Errorf("ValidateUpstream(%q) error = %v, want nil (should normalize)", c, err)
		}
	}
}

func TestValidateUpstreamRejectsNonStandardNumericIP(t *testing.T) {
	allow := testAllowlist()
	for _, c := range []string{
		"http://2130706433:8000",   // decimal
		"http://0177.0.0.1:8000",   // octal
		"http://0x7f.0.0.1:8000",   // hex
		"http://0x7f000001:8000",   // hex single
		"http://017700000001:8000", // octal single
	} {
		if err := ValidateUpstream(c, allow); !errors.Is(err, ErrInvalidUpstream) {
			t.Errorf("ValidateUpstream(%q) error = %v, want ErrInvalidUpstream", c, err)
		}
	}
}

func TestValidateUpstreamAcceptsPrivateIPs(t *testing.T) {
	allow := testAllowlist()
	for _, c := range []string{
		"http://10.0.0.5:8000",
		"http://172.16.4.4:8000",
		"http://192.168.1.10:8000",
		"http://[fd00::1]:8000",
		"http://[fc00::abcd]:8000",
	} {
		if err := ValidateUpstream(c, allow); err != nil {
			t.Errorf("ValidateUpstream(%q) error = %v, want nil", c, err)
		}
	}
}

func TestValidateUpstreamRejectsPublicIPs(t *testing.T) {
	allow := testAllowlist()
	for _, c := range []string{
		"http://8.8.8.8:8000",
		"http://1.1.1.1:8000",
		"http://[2001:4860:4860::8888]:8000",
		"http://[::ffff:8.8.8.8]:8000", // IPv4-mapped public
	} {
		if err := ValidateUpstream(c, allow); !errors.Is(err, ErrInvalidUpstream) {
			t.Errorf("ValidateUpstream(%q) error = %v, want ErrInvalidUpstream", c, err)
		}
	}
}

func TestValidateUpstreamAcceptsIPv4MappedPrivate(t *testing.T) {
	allow := testAllowlist()
	if err := ValidateUpstream("http://[::ffff:10.0.0.1]:8000", allow); err != nil {
		t.Errorf("IPv4-mapped private should be accepted, got %v", err)
	}
}

func TestValidateUpstreamRejectsLoopbackAndLinkLocal(t *testing.T) {
	allow := testAllowlist()
	for _, c := range []string{
		"http://127.0.0.1",
		"http://127.0.0.5",
		"http://[::1]",
		"http://[::ffff:127.0.0.1]",
		"http://169.254.169.254/latest/meta-data",
		"http://[fe80::1]",
		"http://0.0.0.0",
	} {
		if err := ValidateUpstream(c, allow); !errors.Is(err, ErrInvalidUpstream) {
			t.Errorf("ValidateUpstream(%q) error = %v, want ErrInvalidUpstream", c, err)
		}
	}
}

func TestValidateUpstreamRejectsReservedHostnames(t *testing.T) {
	// Even if an admin mistakenly allowlists these, loopback-resolving names and
	// the cloud metadata host must never be accepted.
	allow := NewUpstreamAllowlist("localhost", "metadata.google.internal", "metadata")
	for _, c := range []string{
		"http://localhost:8000",
		"http://metadata.google.internal",
		"http://metadata",
	} {
		if err := ValidateUpstream(c, allow); !errors.Is(err, ErrInvalidUpstream) {
			t.Errorf("ValidateUpstream(%q) error = %v, want ErrInvalidUpstream (reserved)", c, err)
		}
	}
}

func TestValidateUpstreamRejectsBadScheme(t *testing.T) {
	allow := testAllowlist()
	for _, c := range []string{
		"ftp://image-compressor",
		"file:///etc/passwd",
		"gopher://image-compressor",
		"javascript://image-compressor",
	} {
		if err := ValidateUpstream(c, allow); !errors.Is(err, ErrInvalidUpstream) {
			t.Errorf("ValidateUpstream(%q) error = %v, want ErrInvalidUpstream", c, err)
		}
	}
}

func TestValidateUpstreamRejectsUserInfo(t *testing.T) {
	allow := testAllowlist()
	if err := ValidateUpstream("http://user:pass@image-compressor:8000", allow); !errors.Is(err, ErrInvalidUpstream) {
		t.Errorf("userinfo should be rejected, got %v", err)
	}
}

func TestValidateUpstreamRejectsDisallowedPort(t *testing.T) {
	allow := testAllowlist()
	for _, c := range []string{
		"http://image-compressor:22",
		"http://image-compressor:3306",
		"http://image-compressor:6379",
	} {
		if err := ValidateUpstream(c, allow); !errors.Is(err, ErrInvalidUpstream) {
			t.Errorf("ValidateUpstream(%q) error = %v, want ErrInvalidUpstream", c, err)
		}
	}
}

func TestValidateUpstreamRejectsEmptyAndGarbage(t *testing.T) {
	allow := testAllowlist()
	for _, c := range []string{"", "   ", "not a url", "://missing-scheme"} {
		if err := ValidateUpstream(c, allow); !errors.Is(err, ErrInvalidUpstream) {
			t.Errorf("ValidateUpstream(%q) error = %v, want ErrInvalidUpstream", c, err)
		}
	}
}

func TestValidateUpstreamRejectsEverythingWithEmptyAllowlist(t *testing.T) {
	// Default-deny: with no configured allowlist, no hostname is permitted.
	empty := NewUpstreamAllowlist()
	if err := ValidateUpstream("http://image-compressor:8000", empty); !errors.Is(err, ErrInvalidUpstream) {
		t.Errorf("empty allowlist should reject hostnames, got %v", err)
	}
	// Private IP literals remain acceptable (they need no allowlist entry).
	if err := ValidateUpstream("http://10.0.0.5:8000", empty); err != nil {
		t.Errorf("private IP should still be accepted with empty allowlist, got %v", err)
	}
}

func TestNormalizeHostname(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"Image-Compressor", "image-compressor", true},
		{"image-compressor.", "image-compressor", true},
		{"a.b.c", "a.b.c", true},
		{"", "", false},
		{"-bad", "", false},
		{"bad-", "", false},
		{"a..b", "", false},
		{"under_score", "", false},
	}
	for _, c := range cases {
		got, ok := normalizeHostname(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("normalizeHostname(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"172.32.0.1", false},
		{"192.168.0.1", true},
		{"8.8.8.8", false},
		{"fd00::1", true},
		{"2001:db8::1", false},
	}
	for _, tt := range tests {
		if got := isPrivateIP(parseIP(t, tt.ip)); got != tt.want {
			t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func parseIP(t *testing.T, s string) (ip net.IP) {
	t.Helper()
	ip = net.ParseIP(s)
	if ip == nil {
		t.Fatalf("bad test IP %q", s)
	}
	return ip
}
