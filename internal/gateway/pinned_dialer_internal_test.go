package gateway

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/winduputra/MyCorePlat/internal/service"
)

// internalResolver is a controlled resolver used only by these in-package tests.
type internalResolver struct {
	mu      sync.Mutex
	answers map[string][]string
	err     error
	calls   int
}

func (r *internalResolver) LookupIP(_ context.Context, host string) ([]net.IP, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.err != nil {
		return nil, r.err
	}
	addrs, ok := r.answers[host]
	if !ok {
		return nil, fmt.Errorf("no such host %q", host)
	}
	out := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			return nil, fmt.Errorf("invalid address %q", addr)
		}
		out = append(out, ip)
	}
	return out, nil
}

func (r *internalResolver) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func (r *internalResolver) setAnswers(host string, addrs ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.answers[host] = addrs
}

// acceptOnce returns a listener plus a channel that fires when a connection is
// accepted.
func acceptOnce(t *testing.T) (net.Listener, chan struct{}) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	accepted := make(chan struct{}, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		accepted <- struct{}{}
		_ = conn.Close()
	}()
	return listener, accepted
}

func TestPinnedDialerDialsTheValidatedAddress(t *testing.T) {
	listener, accepted := acceptOnce(t)
	defer listener.Close()

	resolver := &internalResolver{answers: map[string][]string{"pinned.internal": {"127.0.0.1"}}}
	dialer := &pinnedDialer{
		resolver: resolver,
		policy:   service.NewLoopbackUpstreamPolicyForTests(),
		allow:    service.NewUpstreamAllowlist("pinned.internal"),
		dialer:   &net.Dialer{Timeout: 2 * time.Second},
	}

	_, port, _ := net.SplitHostPort(listener.Addr().String())
	conn, err := dialer.DialContext(context.Background(), "tcp", "pinned.internal:"+port)
	if err != nil {
		t.Fatalf("DialContext() = %v, want nil", err)
	}
	_ = conn.Close()

	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("dial did not reach the validated address")
	}
	if got := resolver.callCount(); got != 1 {
		t.Errorf("resolver calls = %d, want 1 (no repeated lookup at connect time)", got)
	}
}

func TestPinnedDialerRejectsHostnameOutsideAllowlist(t *testing.T) {
	resolver := &internalResolver{answers: map[string][]string{"evil.internal": {"127.0.0.1"}}}
	dialer := &pinnedDialer{
		resolver: resolver,
		policy:   service.NewLoopbackUpstreamPolicyForTests(),
		allow:    service.NewUpstreamAllowlist("pinned.internal"),
		dialer:   &net.Dialer{Timeout: time.Second},
	}

	if _, err := dialer.DialContext(context.Background(), "tcp", "evil.internal:9000"); err == nil {
		t.Fatal("DialContext() = nil, want allowlist rejection")
	}
	if got := resolver.callCount(); got != 0 {
		t.Errorf("resolver calls = %d, want 0 for a non-allowlisted host", got)
	}
}

func TestPinnedDialerRejectsDeniedAddress(t *testing.T) {
	resolver := &internalResolver{answers: map[string][]string{"meta.internal": {"169.254.169.254"}}}
	dialer := &pinnedDialer{
		resolver: resolver,
		policy:   service.NewLoopbackUpstreamPolicyForTests(),
		allow:    service.NewUpstreamAllowlist("meta.internal"),
		dialer:   &net.Dialer{Timeout: time.Second},
	}

	if _, err := dialer.DialContext(context.Background(), "tcp", "meta.internal:80"); err == nil {
		t.Fatal("DialContext() = nil, want address-policy rejection")
	}
}

func TestPinnedDialerNeverFallsBackToAnUnvalidatedLookup(t *testing.T) {
	resolver := &internalResolver{err: fmt.Errorf("dns unavailable")}
	dialer := &pinnedDialer{
		resolver: resolver,
		policy:   service.NewLoopbackUpstreamPolicyForTests(),
		allow:    service.NewUpstreamAllowlist("pinned.internal"),
		dialer:   &net.Dialer{Timeout: time.Second},
	}

	if _, err := dialer.DialContext(context.Background(), "tcp", "pinned.internal:9000"); err == nil {
		t.Fatal("DialContext() = nil, want failure when resolution fails")
	}
}

func TestPinnedDialerRejectsMalformedAddress(t *testing.T) {
	dialer := &pinnedDialer{
		resolver: &internalResolver{answers: map[string][]string{}},
		policy:   service.NewLoopbackUpstreamPolicyForTests(),
		allow:    service.NewUpstreamAllowlist("pinned.internal"),
		dialer:   &net.Dialer{Timeout: time.Second},
	}

	for _, addr := range []string{"missing-port", ":9000", "pinned.internal:"} {
		if _, err := dialer.DialContext(context.Background(), "tcp", addr); err == nil {
			t.Errorf("DialContext(%q) = nil, want error", addr)
		}
	}
}
