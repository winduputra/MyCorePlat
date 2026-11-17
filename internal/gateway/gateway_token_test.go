package gateway_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/winduputra/MyCorePlat/internal/gateway"
	"github.com/winduputra/MyCorePlat/internal/model"
	"github.com/winduputra/MyCorePlat/internal/service"
)

// fakeTokenValidator is an in-test TokenValidator. It records calls so tests can
// assert that validation happened (or was skipped) and how many times.
type fakeTokenValidator struct {
	mu sync.Mutex

	// tokens maps plaintext token -> the AccessToken it authorizes. A nil value
	// means "unknown".
	tokens map[string]*model.AccessToken
	// calls records every Validate call (the plaintext seen).
	calls []string
	// touches records TouchLastUsed ids.
	touches []uint64
}

func newFakeTokenValidator() *fakeTokenValidator {
	return &fakeTokenValidator{tokens: map[string]*model.AccessToken{}}
}

// allow registers a plaintext token authorizing the given tool ID.
func (f *fakeTokenValidator) allow(plaintext string, toolID uint64) {
	f.tokens[plaintext] = &model.AccessToken{ID: toolID, ToolID: toolID}
}

func (f *fakeTokenValidator) Validate(_ context.Context, plaintext string, toolID uint64, now time.Time) (*model.AccessToken, error) {
	f.mu.Lock()
	f.calls = append(f.calls, plaintext)
	token, ok := f.tokens[plaintext]
	f.mu.Unlock()
	if !ok || token.ToolID != toolID {
		return nil, service.ErrAccessTokenInvalid
	}
	return token, nil
}

func (f *fakeTokenValidator) TouchLastUsed(_ context.Context, id uint64, _ time.Time) {
	f.mu.Lock()
	f.touches = append(f.touches, id)
	f.mu.Unlock()
}

func (f *fakeTokenValidator) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// alwaysDenyLimiter rejects every attempt.
type alwaysDenyLimiter struct{}

func (alwaysDenyLimiter) Allow(string) bool { return false }

// alwaysAllowLimiter permits every attempt.
type alwaysAllowLimiter struct{}

func (alwaysAllowLimiter) Allow(string) bool { return true }

// tokenTool builds an active tool requiring a token, with the given ID.
func tokenTool(id uint64, slug, upstream string) *model.Tool {
	tool := activeTool(slug, upstream)
	tool.ID = id
	tool.AccessType = model.ToolAccessToken
	return tool
}

// echoUpstream returns an httptest server that reports the method and echoes a
// marker so tests can confirm the request reached the tool. It records whether
// it was called.
func echoUpstream(t *testing.T) (*httptest.Server, *int) {
	t.Helper()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("X-Tool-Seen", "yes")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("reached-tool"))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

// TestTokenToolWithValidBearerIsProxied is the happy path: a valid token in the
// Authorization header authorizes an access=token tool.
func TestTokenToolWithValidBearerIsProxied(t *testing.T) {
	upstream, calls := echoUpstream(t)
	tool := tokenTool(42, "token-tool", upstream.URL)

	validator := newFakeTokenValidator()
	validator.allow("tbpbj_abc_secretsecret", 42)

	router := newGatewayRouter(t, newLookup(tool), gateway.Options{
		TokenValidator: validator,
	})

	req := httptest.NewRequest(http.MethodGet, "/t/token-tool/ping", nil)
	req.Header.Set("Authorization", "Bearer tbpbj_abc_secretsecret")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	if *calls != 1 {
		t.Fatalf("upstream calls = %d, want 1", *calls)
	}
	if validator.callCount() != 1 {
		t.Fatalf("Validate calls = %d, want 1", validator.callCount())
	}
	if len(validator.touches) != 1 || validator.touches[0] != 42 {
		t.Fatalf("TouchLastUsed = %v, want one call for id 42", validator.touches)
	}
}

// TestTokenToolBearerSchemeIsCaseInsensitive confirms "bearer" is accepted in any
// case, as RFC 7235 requires.
func TestTokenToolBearerSchemeIsCaseInsensitive(t *testing.T) {
	upstream, _ := echoUpstream(t)
	tool := tokenTool(1, "case-tool", upstream.URL)
	validator := newFakeTokenValidator()
	validator.allow("tbpbj_x_secret", 1)
	router := newGatewayRouter(t, newLookup(tool), gateway.Options{TokenValidator: validator})

	req := httptest.NewRequest(http.MethodGet, "/t/case-tool/x", nil)
	req.Header.Set("Authorization", "bEaReR tbpbj_x_secret")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
}

// TestTokenToolRejectsMissingToken: no Authorization header means no access, and
// the generic message must not hint at the reason.
func TestTokenToolRejectsMissingToken(t *testing.T) {
	upstream, calls := echoUpstream(t)
	tool := tokenTool(1, "no-token-tool", upstream.URL)
	validator := newFakeTokenValidator()
	router := newGatewayRouter(t, newLookup(tool), gateway.Options{TokenValidator: validator})

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/t/no-token-tool/x", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if *calls != 0 {
		t.Fatalf("upstream was called %d times, want 0", *calls)
	}
	if validator.callCount() != 0 {
		t.Fatalf("Validate was called without a token")
	}
}

// TestTokenToolRejectsQueryStringToken: a token passed as ?token= or ?access_token=
// must never be accepted.
func TestTokenToolRejectsQueryStringToken(t *testing.T) {
	upstream, calls := echoUpstream(t)
	tool := tokenTool(1, "query-tool", upstream.URL)
	validator := newFakeTokenValidator()
	validator.allow("tbpbj_q_secret", 1)
	router := newGatewayRouter(t, newLookup(tool), gateway.Options{TokenValidator: validator})

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/t/query-tool/x?token=tbpbj_q_secret&access_token=tbpbj_q_secret", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (query tokens must be ignored)", rec.Code)
	}
	if *calls != 0 {
		t.Fatalf("upstream called %d times, want 0", *calls)
	}
}

// TestTokenToolRejectsNonBearerScheme: a bare token or another scheme is refused.
func TestTokenToolRejectsNonBearerScheme(t *testing.T) {
	upstream, _ := echoUpstream(t)
	tool := tokenTool(1, "scheme-tool", upstream.URL)
	validator := newFakeTokenValidator()
	validator.allow("tbpbj_s_secret", 1)
	router := newGatewayRouter(t, newLookup(tool), gateway.Options{TokenValidator: validator})

	for _, header := range []string{"tbpbj_s_secret", "Basic tbpbj_s_secret", "Bearer"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/t/scheme-tool/x", nil)
		req.Header.Set("Authorization", header)
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("header %q status = %d, want 401", header, rec.Code)
		}
	}
}

// TestTokenToolRejectsInvalidToken: an unknown or cross-tool token yields the same
// generic 401 and never contacts the upstream. The body must not reveal which.
func TestTokenToolRejectsInvalidToken(t *testing.T) {
	upstream, calls := echoUpstream(t)
	tool := tokenTool(1, "invalid-tool", upstream.URL)
	validator := newFakeTokenValidator()
	// Token exists but is bound to another tool.
	validator.allow("tbpbj_other_secret", 999)
	router := newGatewayRouter(t, newLookup(tool), gateway.Options{TokenValidator: validator})

	req := httptest.NewRequest(http.MethodGet, "/t/invalid-tool/x", nil)
	req.Header.Set("Authorization", "Bearer tbpbj_other_secret")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if *calls != 0 {
		t.Fatalf("upstream called %d times, want 0", *calls)
	}
	body := strings.ToLower(rec.Body.String())
	for _, leak := range []string{"other", "tool", "expired", "revoked", "unknown", "not found"} {
		if strings.Contains(body, leak) {
			t.Errorf("response body leaks %q: %q", leak, rec.Body.String())
		}
	}
}

// TestTokenToolFailsClosedWithoutValidator: an access=token tool with no validator
// configured must stay closed rather than silently becoming public.
func TestTokenToolFailsClosedWithoutValidator(t *testing.T) {
	upstream, calls := echoUpstream(t)
	tool := tokenTool(1, "closed-tool", upstream.URL)
	router := newGatewayRouter(t, newLookup(tool), gateway.Options{})

	req := httptest.NewRequest(http.MethodGet, "/t/closed-tool/x", nil)
	req.Header.Set("Authorization", "Bearer anything")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (fail closed)", rec.Code)
	}
	if *calls != 0 {
		t.Fatalf("upstream called %d times, want 0", *calls)
	}
}

// TestTokenToolRateLimited: when the limiter rejects, the gateway returns 429 and
// never validates the token or contacts the upstream.
func TestTokenToolRateLimited(t *testing.T) {
	upstream, calls := echoUpstream(t)
	tool := tokenTool(1, "limited-tool", upstream.URL)
	validator := newFakeTokenValidator()
	validator.allow("tbpbj_l_secret", 1)
	router := newGatewayRouter(t, newLookup(tool), gateway.Options{
		TokenValidator:   validator,
		TokenRateLimiter: alwaysDenyLimiter{},
	})

	req := httptest.NewRequest(http.MethodGet, "/t/limited-tool/x", nil)
	req.Header.Set("Authorization", "Bearer tbpbj_l_secret")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if *calls != 0 {
		t.Fatalf("upstream called %d times, want 0", *calls)
	}
	if validator.callCount() != 0 {
		t.Fatalf("Validate was called despite throttling")
	}
}

// TestPublicToolIgnoresTokenAndLimiter: access=public needs no token, and a
// rejected token must not affect it.
func TestPublicToolIgnoresTokenAndLimiter(t *testing.T) {
	upstream, _ := echoUpstream(t)
	tool := activeTool("public-tool", upstream.URL)
	tool.ID = 5
	router := newGatewayRouter(t, newLookup(tool), gateway.Options{
		TokenValidator:   newFakeTokenValidator(),
		TokenRateLimiter: alwaysDenyLimiter{},
	})

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/t/public-tool/x", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("public tool status = %d, want 200", rec.Code)
	}
}

// TestTokenToolAcceptsWithAllowingLimiter: sanity check that permissive throttling
// does not block a valid token.
func TestTokenToolAcceptsWithAllowingLimiter(t *testing.T) {
	upstream, _ := echoUpstream(t)
	tool := tokenTool(7, "allow-lim-tool", upstream.URL)
	validator := newFakeTokenValidator()
	validator.allow("tbpbj_al_secret", 7)
	router := newGatewayRouter(t, newLookup(tool), gateway.Options{
		TokenValidator:   validator,
		TokenRateLimiter: alwaysAllowLimiter{},
	})

	req := httptest.NewRequest(http.MethodGet, "/t/allow-lim-tool/x", nil)
	req.Header.Set("Authorization", "Bearer tbpbj_al_secret")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

// TestTokenToolConcurrentValidationIsSafe runs many concurrent authorized requests
// to catch data races in the validation path.
func TestTokenToolConcurrentValidationIsSafe(t *testing.T) {
	upstream, _ := echoUpstream(t)
	tool := tokenTool(9, "concurrent-tool", upstream.URL)
	validator := newFakeTokenValidator()
	validator.allow("tbpbj_c_secret", 9)
	router := newGatewayRouter(t, newLookup(tool), gateway.Options{TokenValidator: validator})

	const workers = 32
	var wg sync.WaitGroup
	wg.Add(workers)
	errCh := make(chan int, workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/t/concurrent-tool/x", nil)
			req.Header.Set("Authorization", "Bearer tbpbj_c_secret")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				errCh <- rec.Code
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for code := range errCh {
		t.Errorf("concurrent status = %d, want 200", code)
	}
}

// TestTokenToolDoesNotForwardAuthorizationHeader confirms the client's token is
// stripped before reaching the tool (the tool trusts Core's HMAC signature, not
// the caller's token).
func TestTokenToolDoesNotForwardAuthorizationHeader(t *testing.T) {
	var seenAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	tool := tokenTool(11, "strip-auth-tool", upstream.URL)
	validator := newFakeTokenValidator()
	validator.allow("tbpbj_strip_secret", 11)
	router := newGatewayRouter(t, newLookup(tool), gateway.Options{TokenValidator: validator})

	req := httptest.NewRequest(http.MethodGet, "/t/strip-auth-tool/x", nil)
	req.Header.Set("Authorization", "Bearer tbpbj_strip_secret")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if seenAuth != "" {
		t.Fatalf("upstream saw Authorization header %q; the client token must not be forwarded", seenAuth)
	}
}

// assertErrorType is a small helper for future negative-path extension.
var _ = errors.Is
var _ = gin.TestMode
