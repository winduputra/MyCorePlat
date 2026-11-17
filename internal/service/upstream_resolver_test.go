package service

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
)

// stubResolver is a deterministic resolver: no test depends on real DNS.
type stubResolver struct {
	answers map[string][]net.IP
	err     error
	calls   int
	mu      sync.Mutex
}

func (s *stubResolver) LookupIP(_ context.Context, host string) ([]net.IP, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return s.answers[host], nil
}

func (s *stubResolver) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func ips(t *testing.T, addrs ...string) []net.IP {
	t.Helper()
	out := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			t.Fatalf("invalid test address %q", addr)
		}
		out = append(out, ip)
	}
	return out
}

func TestResolveAllowedUpstreamAcceptsPublicFromAllowedCIDR(t *testing.T) {
	resolver := &stubResolver{answers: map[string][]net.IP{"tool.example.net": ips(t, "93.184.216.34")}}
	policy := mustPolicy(t, "93.184.216.0/24")

	got, err := ResolveAllowedUpstream(context.Background(), resolver, "tool.example.net", policy)
	if err != nil {
		t.Fatalf("ResolveAllowedUpstream() = %v, want nil", err)
	}
	if len(got) != 1 || got[0].String() != "93.184.216.34" {
		t.Fatalf("resolved = %v, want [93.184.216.34]", got)
	}
}

func TestResolveAllowedUpstreamAcceptsInternalCIDR(t *testing.T) {
	resolver := &stubResolver{answers: map[string][]net.IP{"image-compressor": ips(t, "172.20.5.7")}}

	got, err := ResolveAllowedUpstream(context.Background(), resolver, "image-compressor", DefaultUpstreamIPPolicy())
	if err != nil {
		t.Fatalf("ResolveAllowedUpstream() = %v, want nil", err)
	}
	if len(got) != 1 || got[0].String() != "172.20.5.7" {
		t.Fatalf("resolved = %v, want [172.20.5.7]", got)
	}
}

func TestResolveAllowedUpstreamRejectsLoopbackAnswers(t *testing.T) {
	resolver := &stubResolver{answers: map[string][]net.IP{"evil.internal": ips(t, "127.0.0.1")}}

	if _, err := ResolveAllowedUpstream(context.Background(), resolver, "evil.internal", mustPolicy(t, "0.0.0.0/0")); !errors.Is(err, ErrUpstreamAddressNotAllowed) {
		t.Errorf("err = %v, want loopback denial", err)
	}
}

func TestResolveAllowedUpstreamRejectsMixedPublicAndPrivate(t *testing.T) {
	resolver := &stubResolver{answers: map[string][]net.IP{
		"mixed.internal": ips(t, "10.0.0.5", "169.254.169.254"),
	}}
	policy := mustPolicy(t, "10.0.0.0/8", "0.0.0.0/0")

	// Even though the first answer is allowed, one denied answer denies the host.
	if _, err := ResolveAllowedUpstream(context.Background(), resolver, "mixed.internal", policy); !errors.Is(err, ErrUpstreamAddressNotAllowed) {
		t.Errorf("err = %v, want denial for mixed answers", err)
	}
}

func TestResolveAllowedUpstreamFailsClosedOnResolverError(t *testing.T) {
	resolver := &stubResolver{err: errors.New("dns timeout")}

	_, err := ResolveAllowedUpstream(context.Background(), resolver, "tool.internal", DefaultUpstreamIPPolicy())
	if !errors.Is(err, ErrUpstreamResolveFailed) {
		t.Errorf("err = %v, want ErrUpstreamResolveFailed", err)
	}
}

func TestResolveAllowedUpstreamFailsClosedOnEmptyAnswer(t *testing.T) {
	resolver := &stubResolver{answers: map[string][]net.IP{"tool.internal": {}}}

	_, err := ResolveAllowedUpstream(context.Background(), resolver, "tool.internal", DefaultUpstreamIPPolicy())
	if !errors.Is(err, ErrUpstreamResolveFailed) {
		t.Errorf("err = %v, want ErrUpstreamResolveFailed", err)
	}
}

func TestResolveAllowedUpstreamFailsClosedWithoutResolver(t *testing.T) {
	_, err := ResolveAllowedUpstream(context.Background(), nil, "tool.internal", DefaultUpstreamIPPolicy())
	if !errors.Is(err, ErrUpstreamResolveFailed) {
		t.Errorf("err = %v, want ErrUpstreamResolveFailed", err)
	}
}

func TestResolveAllowedUpstreamValidatesIPLiteralWithoutResolving(t *testing.T) {
	resolver := &stubResolver{}

	got, err := ResolveAllowedUpstream(context.Background(), resolver, "10.0.0.7", DefaultUpstreamIPPolicy())
	if err != nil {
		t.Fatalf("ResolveAllowedUpstream(literal) = %v, want nil", err)
	}
	if len(got) != 1 || got[0].String() != "10.0.0.7" {
		t.Fatalf("resolved = %v, want [10.0.0.7]", got)
	}
	if resolver.callCount() != 0 {
		t.Errorf("resolver calls = %d, want 0 for an IP literal", resolver.callCount())
	}

	if _, err := ResolveAllowedUpstream(context.Background(), resolver, "93.184.216.34", DefaultUpstreamIPPolicy()); !errors.Is(err, ErrUpstreamAddressNotAllowed) {
		t.Errorf("public literal err = %v, want denial", err)
	}
}

func TestResolveAllowedUpstreamNormalizesIPv4MappedAnswers(t *testing.T) {
	resolver := &stubResolver{answers: map[string][]net.IP{"mapped.internal": ips(t, "::ffff:10.0.0.9")}}

	got, err := ResolveAllowedUpstream(context.Background(), resolver, "mapped.internal", DefaultUpstreamIPPolicy())
	if err != nil {
		t.Fatalf("ResolveAllowedUpstream() = %v, want nil", err)
	}
	if len(got) != 1 || got[0].String() != "10.0.0.9" {
		t.Fatalf("resolved = %v, want IPv4 10.0.0.9", got)
	}
}

func TestResolveAllowedUpstreamDeduplicatesAnswers(t *testing.T) {
	resolver := &stubResolver{answers: map[string][]net.IP{
		"dup.internal": ips(t, "10.0.0.5", "10.0.0.5", "::ffff:10.0.0.5"),
	}}

	got, err := ResolveAllowedUpstream(context.Background(), resolver, "dup.internal", DefaultUpstreamIPPolicy())
	if err != nil {
		t.Fatalf("ResolveAllowedUpstream() = %v, want nil", err)
	}
	if len(got) != 1 {
		t.Fatalf("resolved = %v, want a single deduplicated address", got)
	}
}

func TestResolveAllowedUpstreamIsSafeForConcurrentUse(t *testing.T) {
	resolver := &stubResolver{answers: map[string][]net.IP{"tool.internal": ips(t, "10.0.0.5", "10.0.0.6")}}
	policy := DefaultUpstreamIPPolicy()

	var wg sync.WaitGroup
	errCh := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := ResolveAllowedUpstream(context.Background(), resolver, "tool.internal", policy)
			if err != nil {
				errCh <- err
				return
			}
			if len(got) != 2 {
				errCh <- errors.New("unexpected address count")
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("concurrent resolve failed: %v", err)
	}
}
