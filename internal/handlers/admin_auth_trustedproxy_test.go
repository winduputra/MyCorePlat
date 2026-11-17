package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/winduputra/MyCorePlat/internal/service"
)

// loginBehindProxy performs a login POST with both a fixed TCP peer address and
// an X-Forwarded-For header, so tests can model a request that traversed (or did
// not traverse) a trusted reverse proxy.
func loginBehindProxy(t *testing.T, r *gin.Engine, remoteAddr, forwardedFor string) *httptest.ResponseRecorder {
	t.Helper()
	return loginBehindProxyUser(t, r, remoteAddr, forwardedFor, "admin")
}

// loginBehindProxyUser is loginBehindProxy with an explicit username, so IP-keyed
// behaviour can be isolated from the username-keyed limiter.
func loginBehindProxyUser(t *testing.T, r *gin.Engine, remoteAddr, forwardedFor, username string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"username": {username}, "password": {"x"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = remoteAddr
	if forwardedFor != "" {
		req.Header.Set("X-Forwarded-For", forwardedFor)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// mustResolver builds a resolver for the given trusted proxy entries.
func mustResolver(t *testing.T, trusted ...string) *service.ClientIPResolver {
	t.Helper()
	resolver, err := service.NewClientIPResolver(trusted)
	if err != nil {
		t.Fatalf("NewClientIPResolver(%v): %v", trusted, err)
	}
	return resolver
}

// TestTrustedProxyUsesForwardedIPForLoginLimit asserts that when the peer is a
// trusted proxy, the forwarded client address drives the IP limit: two distinct
// real clients behind the same proxy must not share one bucket.
func TestTrustedProxyUsesForwardedIPForLoginLimit(t *testing.T) {
	fake := &fakeAuthService{loginErr: service.ErrInvalidCredentials}
	h := newLimitedAuthHandler(fake, 2, time.Minute)
	h.SetClientIPResolver(mustResolver(t, "172.18.0.3"))
	r := newAuthTestRouter(h)

	// Client A (36.72.11.9) exhausts its own IP budget: 2 failures, then 429.
	for i := 0; i < 2; i++ {
		if w := loginBehindProxyUser(t, r, "172.18.0.3:40212", "36.72.11.9", "alice"); w.Code == http.StatusTooManyRequests {
			t.Fatalf("client A attempt %d throttled early: %d", i+1, w.Code)
		}
	}
	if w := loginBehindProxyUser(t, r, "172.18.0.3:40212", "36.72.11.9", "alice"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("client A beyond limit = %d, want 429", w.Code)
	}
	// Client B (203.0.113.77) behind the SAME proxy, different username, must be
	// unaffected: proving the IP limiter keyed on the forwarded client, not NPM.
	if w := loginBehindProxyUser(t, r, "172.18.0.3:40213", "203.0.113.77", "bob"); w.Code == http.StatusTooManyRequests {
		t.Fatalf("client B throttled by client A's traffic: status %d", w.Code)
	}
}

// TestUntrustedProxyForwardedIPCannotEscapeLoginLimit asserts that when the peer
// is NOT a trusted proxy, a spoofed X-Forwarded-For cannot open fresh buckets;
// throttling follows the real peer address.
func TestUntrustedProxyForwardedIPCannotEscapeLoginLimit(t *testing.T) {
	fake := &fakeAuthService{loginErr: service.ErrInvalidCredentials}
	h := newLimitedAuthHandler(fake, 2, time.Minute)
	h.SetClientIPResolver(mustResolver(t, "172.18.0.3"))
	r := newAuthTestRouter(h)

	if w := loginBehindProxyUser(t, r, "45.33.10.20:5555", "1.1.1.1", "u1"); w.Code == http.StatusTooManyRequests {
		t.Fatalf("attempt 1 throttled: %d", w.Code)
	}
	if w := loginBehindProxyUser(t, r, "45.33.10.20:5555", "8.8.8.8", "u2"); w.Code == http.StatusTooManyRequests {
		t.Fatalf("attempt 2 throttled: %d", w.Code)
	}
	// Third attempt from the same peer with distinct username and yet another
	// spoofed address is still blocked: the header was ignored, so the peer IP
	// bucket is already exhausted (neither username nor forwarded IP helped).
	if w := loginBehindProxyUser(t, r, "45.33.10.20:5555", "9.9.9.9", "u3"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("spoofed forwarded-for escaped the login limit: status %d, want 429", w.Code)
	}
}

// TestNoTrustedProxiesKeepsPeerThrottling is the default: with no trusted
// proxies configured, throttling keys on the peer address and ignores headers.
func TestNoTrustedProxiesKeepsPeerThrottling(t *testing.T) {
	fake := &fakeAuthService{loginErr: service.ErrInvalidCredentials}
	h := newLimitedAuthHandler(fake, 2, time.Minute)
	h.SetClientIPResolver(mustResolver(t)) // trust nothing
	r := newAuthTestRouter(h)

	for i := 0; i < 2; i++ {
		u := "n" + string(rune('1'+i))
		if w := loginBehindProxyUser(t, r, "45.33.10.20:5555", "1.2.3.4", u); w.Code == http.StatusTooManyRequests {
			t.Fatalf("attempt %d throttled early: %d", i+1, w.Code)
		}
	}
	if w := loginBehindProxyUser(t, r, "45.33.10.20:5555", "5.6.7.8", "n9"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("default resolver ignored peer for limiter: status %d, want 429", w.Code)
	}
}
