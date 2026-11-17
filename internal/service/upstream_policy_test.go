package service

import (
	"errors"
	"net"
	"testing"
)

func mustPolicy(t *testing.T, cidrs ...string) UpstreamIPPolicy {
	t.Helper()
	policy, err := NewUpstreamIPPolicy(cidrs)
	if err != nil {
		t.Fatalf("NewUpstreamIPPolicy(%v): %v", cidrs, err)
	}
	return policy
}

func TestUpstreamIPPolicyAllowsAddressInConfiguredCIDR(t *testing.T) {
	policy := mustPolicy(t, "10.0.0.0/8")

	for _, addr := range []string{"10.0.0.1", "10.255.255.254", "::ffff:10.1.2.3"} {
		if err := policy.Permits(net.ParseIP(addr)); err != nil {
			t.Errorf("Permits(%s) = %v, want nil", addr, err)
		}
	}
}

func TestUpstreamIPPolicyAllowsPublicAddressOnlyWhenConfigured(t *testing.T) {
	public := net.ParseIP("93.184.216.34")

	if err := DefaultUpstreamIPPolicy().Permits(public); !errors.Is(err, ErrUpstreamAddressNotAllowed) {
		t.Errorf("default policy Permits(public) = %v, want denial", err)
	}
	if err := mustPolicy(t, "93.184.216.0/24").Permits(public); err != nil {
		t.Errorf("explicitly allowed public Permits() = %v, want nil", err)
	}
}

func TestUpstreamIPPolicyDeniesLoopback(t *testing.T) {
	policy := mustPolicy(t, "0.0.0.0/0")

	for _, addr := range []string{"127.0.0.1", "127.10.10.10", "::1", "::ffff:127.0.0.1"} {
		if err := policy.Permits(net.ParseIP(addr)); !errors.Is(err, ErrUpstreamAddressNotAllowed) {
			t.Errorf("Permits(%s) = %v, want loopback denial", addr, err)
		}
	}
}

func TestUpstreamIPPolicyDeniesLinkLocalAndMetadata(t *testing.T) {
	policy := mustPolicy(t, "0.0.0.0/0", "::/0")

	for _, addr := range []string{
		"169.254.169.254", // cloud metadata (IPv4)
		"169.254.0.1",     // link-local
		"fe80::1",         // link-local (IPv6)
		"fd00:ec2::254",   // cloud metadata (IPv6)
		"100.100.100.200", // carrier-grade NAT metadata endpoint
	} {
		if err := policy.Permits(net.ParseIP(addr)); !errors.Is(err, ErrUpstreamAddressNotAllowed) {
			t.Errorf("Permits(%s) = %v, want denial", addr, err)
		}
	}
}

func TestUpstreamIPPolicyDeniesMulticastUnspecifiedAndReserved(t *testing.T) {
	policy := mustPolicy(t, "0.0.0.0/0", "::/0")

	for _, addr := range []string{
		"0.0.0.0",
		"::",
		"224.0.0.1",
		"ff02::1",
		"255.255.255.255",
		"240.0.0.1",
		"192.0.2.10",
		"198.18.0.1",
		"198.51.100.7",
		"203.0.113.9",
		"2001:db8::1",
		"fec0::1",
	} {
		if err := policy.Permits(net.ParseIP(addr)); !errors.Is(err, ErrUpstreamAddressNotAllowed) {
			t.Errorf("Permits(%s) = %v, want denial", addr, err)
		}
	}
}

func TestUpstreamIPPolicyDeniesAddressOutsideCIDR(t *testing.T) {
	policy := mustPolicy(t, "172.16.0.0/12")

	if err := policy.Permits(net.ParseIP("10.1.2.3")); !errors.Is(err, ErrUpstreamAddressNotAllowed) {
		t.Errorf("Permits(10.1.2.3) = %v, want denial (outside CIDR)", err)
	}
	if err := policy.Permits(net.ParseIP("fc00::10")); !errors.Is(err, ErrUpstreamAddressNotAllowed) {
		t.Errorf("Permits(fc00::10) = %v, want denial (outside CIDR)", err)
	}
}

func TestUpstreamIPPolicyZeroValueDeniesEverything(t *testing.T) {
	var policy UpstreamIPPolicy

	if policy.IsConfigured() {
		t.Error("zero policy reports configured")
	}
	if err := policy.Permits(net.ParseIP("10.0.0.1")); err == nil {
		t.Error("zero policy Permits() = nil, want denial")
	}
	if err := policy.Permits(nil); err == nil {
		t.Error("zero policy Permits(nil) = nil, want denial")
	}
}

func TestUpstreamIPPolicyRejectsEmptyAndInvalidCIDRs(t *testing.T) {
	if _, err := NewUpstreamIPPolicy(nil); err == nil {
		t.Error("NewUpstreamIPPolicy(nil) = nil, want error")
	}
	if _, err := NewUpstreamIPPolicy([]string{"10.0.0.0/8", "not-a-cidr"}); err == nil {
		t.Error("NewUpstreamIPPolicy(invalid) = nil, want error")
	}
}

func TestDefaultUpstreamIPPolicyAllowsInternalRanges(t *testing.T) {
	policy := DefaultUpstreamIPPolicy()

	if !policy.IsConfigured() {
		t.Fatal("default policy not configured")
	}
	if err := policy.Permits(net.ParseIP("10.0.0.5")); err != nil {
		t.Errorf("Permits(10.0.0.5) = %v, want nil", err)
	}
	if err := policy.Permits(net.ParseIP("172.20.0.5")); err != nil {
		t.Errorf("Permits(172.20.0.5) = %v, want nil", err)
	}
	if err := policy.Permits(net.ParseIP("192.168.5.5")); err != nil {
		t.Errorf("Permits(192.168.5.5) = %v, want nil", err)
	}
	if err := policy.Permits(net.ParseIP("fd00::5")); err != nil {
		t.Errorf("Permits(fd00::5) = %v, want nil", err)
	}
}

func TestLoopbackUpstreamPolicyForTestsAllowsLoopbackOnly(t *testing.T) {
	policy := NewLoopbackUpstreamPolicyForTests()

	if err := policy.Permits(net.ParseIP("127.0.0.1")); err != nil {
		t.Errorf("Permits(127.0.0.1) = %v, want nil", err)
	}
	if err := policy.Permits(net.ParseIP("::1")); err != nil {
		t.Errorf("Permits(::1) = %v, want nil", err)
	}
	if err := policy.Permits(net.ParseIP("169.254.169.254")); !errors.Is(err, ErrUpstreamAddressNotAllowed) {
		t.Errorf("Permits(169.254.169.254) = %v, want denial even in test policy", err)
	}
	if err := policy.Permits(net.ParseIP("93.184.216.34")); !errors.Is(err, ErrUpstreamAddressNotAllowed) {
		t.Errorf("Permits(public) = %v, want denial", err)
	}
}
