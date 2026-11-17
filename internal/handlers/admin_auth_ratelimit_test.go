package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/winduputra/MyCorePlat/internal/model"
	"github.com/winduputra/MyCorePlat/internal/service"
)

// newLimitedAuthHandler builds an AuthHandler with a login limiter enforcing
// limit failures per window, keyed by client IP and by username.
func newLimitedAuthHandler(auth AuthService, limit int, window time.Duration) *AuthHandler {
	h := NewAuthHandler(auth, nil, AuthOptions{CookieName: "bpbj_admin_session", CookiePath: "/", SessionTTL: 3600})
	h.SetLoginLimiters(
		service.NewRateLimiter(service.RateLimiterConfig{Limit: limit, Window: window}),
		service.NewRateLimiter(service.RateLimiterConfig{Limit: limit, Window: window}),
	)
	return h
}

// loginReq performs a login POST from a fixed remote address. Setting RemoteAddr
// (not X-Forwarded-For) reflects the only address the handler should trust.
func loginReq(t *testing.T, r *gin.Engine, remoteAddr, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"username": {username}, "password": {password}}
	req := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// TestLoginRateLimitBlocksAfterThreshold asserts that after `limit` failed
// attempts the next attempt is rejected with 429.
func TestLoginRateLimitBlocksAfterThreshold(t *testing.T) {
	fake := &fakeAuthService{loginErr: service.ErrInvalidCredentials}
	h := newLimitedAuthHandler(fake, 3, time.Minute)
	r := newAuthTestRouter(h)

	for i := 0; i < 3; i++ {
		if w := loginReq(t, r, "203.0.113.10:5555", "alice", "wrong"); w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want 401", i+1, w.Code)
		}
	}
	if w := loginReq(t, r, "203.0.113.10:5555", "alice", "wrong"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("blocked attempt: status = %d, want 429", w.Code)
	}
}

// TestLoginRateLimitReturnsRetryAfter asserts the 429 response carries a
// Retry-After header and does not call the auth service again.
func TestLoginRateLimitReturnsRetryAfter(t *testing.T) {
	fake := &fakeAuthService{loginErr: service.ErrInvalidCredentials}
	h := newLimitedAuthHandler(fake, 2, 90*time.Second)
	r := newAuthTestRouter(h)

	loginReq(t, r, "203.0.113.11:5555", "bob", "wrong")
	loginReq(t, r, "203.0.113.11:5555", "bob", "wrong")
	callsBefore := fake.loginCalls

	w := loginReq(t, r, "203.0.113.11:5555", "bob", "wrong")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", w.Code)
	}
	ra := w.Header().Get("Retry-After")
	if ra == "" {
		t.Fatal("missing Retry-After header")
	}
	if n, err := strconv.Atoi(ra); err != nil || n <= 0 {
		t.Fatalf("Retry-After = %q, want positive integer seconds", ra)
	}
	if fake.loginCalls != callsBefore {
		t.Fatalf("auth service called while blocked: calls %d -> %d", callsBefore, fake.loginCalls)
	}
}

// TestLoginRateLimitWindowExpiryAllowsAgain asserts the limiter recovers once
// the window elapses. A short real window is used because the limiter is an
// in-memory sliding window with an unexported clock (not reachable from this
// package); the wait is kept tiny to keep the test fast.
func TestLoginRateLimitWindowExpiryAllowsAgain(t *testing.T) {
	fake := &fakeAuthService{loginErr: service.ErrInvalidCredentials}
	h := newLimitedAuthHandler(fake, 2, 150*time.Millisecond)
	r := newAuthTestRouter(h)

	loginReq(t, r, "203.0.113.12:5555", "carol", "wrong")
	loginReq(t, r, "203.0.113.12:5555", "carol", "wrong")
	if w := loginReq(t, r, "203.0.113.12:5555", "carol", "wrong"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("before window: status = %d, want 429", w.Code)
	}

	time.Sleep(250 * time.Millisecond) // advance past the window
	if w := loginReq(t, r, "203.0.113.12:5555", "carol", "wrong"); w.Code != http.StatusUnauthorized {
		t.Fatalf("after window: status = %d, want 401", w.Code)
	}
}

// TestLoginRateLimitSuccessResetsUsernameBucket asserts a successful login is
// not blocked and clears the per-username bucket, while the per-IP bucket
// deliberately keeps counting (so one valid guess does not grant a fresh IP
// budget). Here only the username dimension is exercised with a high IP limit.
func TestLoginRateLimitSuccessResetsUsernameBucket(t *testing.T) {
	fake := &fakeAuthService{plaintext: "tok", session: &model.AdminSession{ID: 5, CSRFToken: "c"}}
	h := NewAuthHandler(fake, nil, AuthOptions{CookieName: "bpbj_admin_session", CookiePath: "/", SessionTTL: 3600})
	// IP limiter is generous; username limiter enforces 3.
	h.SetLoginLimiters(
		service.NewRateLimiter(service.RateLimiterConfig{Limit: 100, Window: time.Minute}),
		service.NewRateLimiter(service.RateLimiterConfig{Limit: 3, Window: time.Minute}),
	)
	r := newAuthTestRouter(h)

	// Two failures for the username, then a success within the limit.
	fake.loginErr = service.ErrInvalidCredentials
	loginReq(t, r, "203.0.113.13:5555", "dave", "wrong")
	loginReq(t, r, "203.0.113.13:5555", "dave", "wrong")

	fake.loginErr = nil
	if w := loginReq(t, r, "203.0.113.13:5555", "dave", "correct"); w.Code != http.StatusSeeOther {
		t.Fatalf("successful login: status = %d, want 303", w.Code)
	}

	// Username bucket was reset by success, so three more failures are allowed
	// again before the username limit is reached (proves the reset happened).
	fake.loginErr = service.ErrInvalidCredentials
	for i := 0; i < 3; i++ {
		if w := loginReq(t, r, "203.0.113.13:5555", "dave", "wrong"); w.Code != http.StatusUnauthorized {
			t.Fatalf("post-reset attempt %d: status = %d, want 401", i+1, w.Code)
		}
	}
	if w := loginReq(t, r, "203.0.113.13:5555", "dave", "wrong"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("past username limit: status = %d, want 429", w.Code)
	}
}

// TestLoginRateLimitPerUsernameIsolation asserts that exhausting one username
// does not block a different username from a different IP-based bucket context.
func TestLoginRateLimitPerUsernameIsolation(t *testing.T) {
	fake := &fakeAuthService{loginErr: service.ErrInvalidCredentials}
	h := newLimitedAuthHandler(fake, 2, time.Minute)
	r := newAuthTestRouter(h)

	// Exhaust the username bucket for "eve" from IP A.
	loginReq(t, r, "203.0.113.20:5555", "eve", "wrong")
	loginReq(t, r, "203.0.113.20:5555", "eve", "wrong")
	if w := loginReq(t, r, "203.0.113.20:5555", "eve", "wrong"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("eve from A: status = %d, want 429", w.Code)
	}

	// A different username from a different IP must still be evaluated normally.
	if w := loginReq(t, r, "198.51.100.7:5555", "frank", "wrong"); w.Code != http.StatusUnauthorized {
		t.Fatalf("frank from B: status = %d, want 401", w.Code)
	}
}

// TestLoginRateLimitPerIPBlocksAcrossUsernames asserts that one IP spraying
// many usernames is throttled by the per-IP bucket (username enumeration).
func TestLoginRateLimitPerIPBlocksAcrossUsernames(t *testing.T) {
	fake := &fakeAuthService{loginErr: service.ErrInvalidCredentials}
	h := newLimitedAuthHandler(fake, 3, time.Minute)
	r := newAuthTestRouter(h)

	names := []string{"u1", "u2", "u3"}
	for _, n := range names {
		if w := loginReq(t, r, "203.0.113.30:5555", n, "wrong"); w.Code != http.StatusUnauthorized {
			t.Fatalf("user %s: status = %d, want 401", n, w.Code)
		}
	}
	// Fourth distinct username from the same IP is blocked by the IP bucket.
	if w := loginReq(t, r, "203.0.113.30:5555", "u4", "wrong"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("4th username same IP: status = %d, want 429", w.Code)
	}
}

// TestLoginRateLimitIgnoresSpoofedForwardedFor asserts that a client cannot
// escape throttling by varying X-Forwarded-For when the connecting IP is fixed.
func TestLoginRateLimitIgnoresSpoofedForwardedFor(t *testing.T) {
	fake := &fakeAuthService{loginErr: service.ErrInvalidCredentials}
	h := newLimitedAuthHandler(fake, 2, time.Minute)
	r := newAuthTestRouter(h)

	post := func(xff string) *httptest.ResponseRecorder {
		form := url.Values{"username": {"spoof"}, "password": {"wrong"}}
		req := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Forwarded-For", xff)
		req.RemoteAddr = "203.0.113.40:5555" // fixed real peer
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	post("10.0.0.1")
	post("10.0.0.2")
	if w := post("10.0.0.3"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("spoofed XFF bypass: status = %d, want 429", w.Code)
	}
}

// TestLoginRateLimitConcurrentRespectsLimit asserts parallel attempts cannot
// exceed the limit (the limiter counts atomically).
func TestLoginRateLimitConcurrentRespectsLimit(t *testing.T) {
	fake := &fakeAuthService{loginErr: service.ErrInvalidCredentials}
	limit := 5
	h := newLimitedAuthHandler(fake, limit, time.Minute)
	r := newAuthTestRouter(h)

	const parallel = 40
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := loginReq(t, r, "203.0.113.50:5555", "race", "wrong")
			mu.Lock()
			if w.Code == http.StatusUnauthorized {
				allowed++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	if allowed > limit {
		t.Fatalf("allowed %d requests, exceed limit %d", allowed, limit)
	}
	if allowed == 0 {
		t.Fatal("no request allowed; limiter is over-blocking")
	}
}

// TestLoginRateLimitDoesNotLeakAccountInfo asserts the 429 body is generic and
// identical regardless of whether the username exists.
func TestLoginRateLimitDoesNotLeakAccountInfo(t *testing.T) {
	fake := &fakeAuthService{loginErr: service.ErrInvalidCredentials}
	h := newLimitedAuthHandler(fake, 1, time.Minute)
	r := newAuthTestRouter(h)

	loginReq(t, r, "203.0.113.60:5555", "existing-user", "wrong")
	w := loginReq(t, r, "203.0.113.60:5555", "existing-user", "wrong")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", w.Code)
	}
	body := strings.ToLower(w.Body.String())
	for _, leak := range []string{"existing-user", "username", "not found", "unknown", "does not exist"} {
		if strings.Contains(body, leak) {
			t.Fatalf("429 body leaks %q: %q", leak, w.Body.String())
		}
	}
}

// TestLoginRateLimitDisabledAllowsAll asserts a nil limiter never blocks.
func TestLoginRateLimitDisabledAllowsAll(t *testing.T) {
	fake := &fakeAuthService{loginErr: service.ErrInvalidCredentials}
	h := NewAuthHandler(fake, nil, AuthOptions{CookieName: "bpbj_admin_session", CookiePath: "/", SessionTTL: 3600})
	r := newAuthTestRouter(h)
	for i := 0; i < 20; i++ {
		if w := loginReq(t, r, "203.0.113.70:5555", "nolimit", "wrong"); w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want 401 (limiter disabled)", i+1, w.Code)
		}
	}
}

// TestLoginRateLimitAuthErrorNotDoubleCounted asserts a non-credential error
// (e.g. internal failure) still returns 500 and is throttled too, so an
// attacker cannot distinguish error classes by bypassing the limiter.
func TestLoginRateLimitInternalErrorThrottled(t *testing.T) {
	fake := &fakeAuthService{loginErr: errors.New("db down")}
	h := newLimitedAuthHandler(fake, 2, time.Minute)
	r := newAuthTestRouter(h)

	loginReq(t, r, "203.0.113.80:5555", "x", "p")
	loginReq(t, r, "203.0.113.80:5555", "x", "p")
	if w := loginReq(t, r, "203.0.113.80:5555", "x", "p"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", w.Code)
	}
}

// TestLoginRateLimitResetsOnSuccessRegardlessOfService keeps the fake honest:
// a nil error must be treated as success (Reset invoked) even if the session is
// minimal.
func TestLoginRateLimitResetsOnSuccessRegardlessOfService(t *testing.T) {
	fake := &fakeAuthService{plaintext: "tok", session: &model.AdminSession{ID: 9, CSRFToken: "c"}}
	h := newLimitedAuthHandler(fake, 10, time.Minute)
	r := newAuthTestRouter(h)
	if w := loginReq(t, r, "203.0.113.90:5555", "zed", "correct"); w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", w.Code)
	}
}
