package router

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/winduputra/MyCorePlat/internal/gateway"
	"github.com/winduputra/MyCorePlat/internal/handlers"
	"github.com/winduputra/MyCorePlat/internal/model"
	"github.com/winduputra/MyCorePlat/internal/service"
)

// stubValidator is a minimal SessionValidator for router tests.
type stubValidator struct{ err error }

func (s stubValidator) Validate(_ context.Context, _ string) (*model.AdminSession, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &model.AdminSession{ID: 1, AdminID: 2, CSRFToken: "csrf"}, nil
}

type stubAuth struct{}

func (stubAuth) Login(_ context.Context, _, _ string, _ service.SessionMeta) (string, *model.AdminSession, error) {
	return "", nil, service.ErrInvalidCredentials
}
func (stubAuth) Logout(_ context.Context, _ uint64) error { return nil }

// stubLoginCSRF is a LoginCSRFVerifier whose Verify always succeeds, so tests
// can exercise the double-submit equality check independently of HMAC.
type stubLoginCSRF struct{ err error }

func (s stubLoginCSRF) Verify(_ string) error { return s.err }

// stubIssuer always returns a fixed pre-auth token so the login page renders.
type stubIssuer struct{}

func (stubIssuer) Issue() (string, time.Time, error) {
	return "pre-auth-token", time.Now().Add(time.Minute), nil
}

// stubToolService is a no-op ToolService so router tests can construct a real
// AdminToolsHandler without a database.
type stubToolService struct{}

func (stubToolService) List(_ context.Context) ([]model.Tool, error) { return nil, nil }
func (stubToolService) Get(_ context.Context, _ uint64) (*model.Tool, error) {
	return nil, service.ErrToolNotFound
}
func (stubToolService) Create(_ context.Context, _ service.ToolInput) (*model.Tool, error) {
	return nil, service.ErrToolNotFound
}
func (stubToolService) Update(_ context.Context, _ uint64, _ service.ToolInput) (*model.Tool, error) {
	return nil, service.ErrToolNotFound
}
func (stubToolService) Delete(_ context.Context, _ uint64) error { return service.ErrToolNotFound }

// stubTokenService is a no-op TokenService so router tests can construct a real
// AdminTokensHandler without a database.
type stubTokenService struct{}

func (stubTokenService) Create(_ context.Context, _ service.AccessTokenInput, _ time.Time) (string, *model.AccessToken, error) {
	return "", nil, service.ErrAccessTokenInvalidInput
}
func (stubTokenService) Validate(_ context.Context, _ string, _ uint64, _ time.Time) (*model.AccessToken, error) {
	return nil, service.ErrAccessTokenInvalid
}
func (stubTokenService) Revoke(_ context.Context, _, _ uint64, _ time.Time) error {
	return service.ErrAccessTokenNotFound
}
func (stubTokenService) ListByTool(_ context.Context, _ uint64) ([]model.AccessToken, error) {
	return nil, nil
}

func newTestDeps() Deps {
	toolsHandler, err := handlers.NewAdminToolsHandler(stubToolService{}, handlers.AdminToolsOptions{})
	if err != nil {
		panic(err)
	}
	tokensHandler, err := handlers.NewAdminTokensHandler(stubToolService{}, stubTokenService{}, handlers.AdminTokensOptions{})
	if err != nil {
		panic(err)
	}
	activityHandler, err := handlers.NewAdminActivityHandler(stubActivityLister{})
	if err != nil {
		panic(err)
	}
	healthHandler, err := handlers.NewAdminHealthHandler(stubToolService{}, stubHealthSnapshotter{})
	if err != nil {
		panic(err)
	}
	return Deps{
		Auth:              handlers.NewAuthHandler(stubAuth{}, stubIssuer{}, handlers.AuthOptions{CookieName: "bpbj_admin_session", CookiePath: "/", SessionTTL: 3600, PreAuthCSRFTTL: 600}),
		Tools:             toolsHandler,
		Tokens:            tokensHandler,
		Activity:          activityHandler,
		Health:            healthHandler,
		SessionValidator:  stubValidator{},
		SessionCookieName: "bpbj_admin_session",
		LoginCSRFVerifier: stubLoginCSRF{},
	}
}

// stubActivityLister is a no-op audit lister for router tests.
type stubActivityLister struct{}

func (stubActivityLister) List(_ context.Context, _ service.ActivityFilter) ([]model.ActivityLog, int64, error) {
	return nil, 0, nil
}

// stubHealthSnapshotter is a no-op health snapshot reader for router tests.
type stubHealthSnapshotter struct{}

func (stubHealthSnapshotter) LatestByTool(_ context.Context, _ []uint64) (map[uint64]*model.ToolHealthCheck, error) {
	return map[uint64]*model.ToolHealthCheck{}, nil
}

func TestNewRegistersHealthRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := New(Deps{})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /health status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestAdminLoginRoutesRegistered(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := New(newTestDeps())

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/login", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/login status = %d, want 200", rec.Code)
	}
}

func TestAdminLogoutRequiresAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// Validator always fails → protected route must reject unauthenticated call.
	deps := newTestDeps()
	deps.SessionValidator = stubValidator{err: errors.New("invalid")}
	r := New(deps)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/logout", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("POST /admin/logout without auth status = %d, want 401", rec.Code)
	}
}

func TestAdminLogoutRequiresCSRF(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := New(newTestDeps())

	// Valid session cookie but no CSRF token → 403.
	req := httptest.NewRequest(http.MethodPost, "/admin/logout", nil)
	req.AddCookie(&http.Cookie{Name: "bpbj_admin_session", Value: "tok"})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST /admin/logout without CSRF status = %d, want 403", rec.Code)
	}
}

func TestAdminLoginPostRequiresPreAuthCSRF(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := New(newTestDeps())

	// POST /admin/login without the pre-auth CSRF cookie/token → 403.
	req := httptest.NewRequest(http.MethodPost, "/admin/login", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST /admin/login without pre-auth CSRF status = %d, want 403", rec.Code)
	}
}

func TestToolsRequireAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	deps := newTestDeps()
	deps.SessionValidator = stubValidator{err: errors.New("invalid")}
	r := New(deps)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/tools", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /admin/tools without auth status = %d, want 401", rec.Code)
	}
}

func TestToolsMutationRequiresCSRF(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := New(newTestDeps())

	// Valid session cookie but no CSRF token on a mutating request → 403.
	req := httptest.NewRequest(http.MethodPost, "/admin/tools", nil)
	req.AddCookie(&http.Cookie{Name: "bpbj_admin_session", Value: "tok"})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST /admin/tools without CSRF status = %d, want 403", rec.Code)
	}
}

// TestTokenRoutesRequireAuth: the token management routes are behind the session
// middleware; an unauthenticated request is refused.
func TestTokenRoutesRequireAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	deps := newTestDeps()
	deps.SessionValidator = stubValidator{err: errors.New("invalid")}
	r := New(deps)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/tools/1/tokens", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /admin/tools/1/tokens without auth status = %d, want 401", rec.Code)
	}
}

// TestTokenMutationRequiresCSRF: minting a token is a mutating request and must
// carry a CSRF token even with a valid session.
func TestTokenMutationRequiresCSRF(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := New(newTestDeps())

	req := httptest.NewRequest(http.MethodPost, "/admin/tools/1/tokens", nil)
	req.AddCookie(&http.Cookie{Name: "bpbj_admin_session", Value: "tok"})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST /admin/tools/1/tokens without CSRF status = %d, want 403", rec.Code)
	}
}

// stubGatewayLookup satisfies gateway.ToolLookup without a database.
type stubGatewayLookup struct{ tools map[string]*model.Tool }

func (s stubGatewayLookup) GetBySlug(_ context.Context, slug string) (*model.Tool, error) {
	if tool, ok := s.tools[slug]; ok {
		return tool, nil
	}
	return nil, service.ErrToolNotFound
}

// newPublicGateway builds a gateway whose upstream validation is overridden,
// since httptest upstreams listen on 127.0.0.1 with a random port that the
// production validator correctly rejects.
func newPublicGateway(t *testing.T, tools ...*model.Tool) *gateway.Gateway {
	t.Helper()
	lookup := map[string]*model.Tool{}
	for _, tool := range tools {
		lookup[tool.Slug] = tool
	}
	return gateway.New(stubGatewayLookup{tools: lookup}, gateway.Options{
		UpstreamValidator: func(string) error { return nil },
		// httptest upstreams listen on 127.0.0.1, which the production address
		// policy denies on purpose.
		IPPolicy: service.NewLoopbackUpstreamPolicyForTests(),
	})
}

func TestGatewayRouteIsPublicAndProxies(t *testing.T) {
	gin.SetMode(gin.TestMode)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello from tool"))
	}))
	defer upstream.Close()

	deps := newTestDeps()
	// Protected routes must still reject an unauthenticated caller.
	deps.SessionValidator = stubValidator{err: errors.New("invalid")}
	deps.Gateway = newPublicGateway(t, &model.Tool{
		ID:              1,
		Slug:            "public-tool",
		Name:            "Public Tool",
		AccessType:      model.ToolAccessPublic,
		Status:          model.ToolStatusActive,
		UpstreamURL:     upstream.URL,
		HealthcheckPath: "/health",
	})
	r := New(deps)

	// The gateway route needs no session cookie at all.
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/t/public-tool/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /t/public-tool/ status = %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); body != "hello from tool" {
		t.Fatalf("GET /t/public-tool/ body = %q, want %q", body, "hello from tool")
	}

	// Admin routes remain protected even though the gateway is public.
	adminRec := httptest.NewRecorder()
	r.ServeHTTP(adminRec, httptest.NewRequest(http.MethodGet, "/admin/tools", nil))
	if adminRec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /admin/tools status = %d, want 401", adminRec.Code)
	}
}

func TestGatewayRouteRegisteredForUnknownTool(t *testing.T) {
	gin.SetMode(gin.TestMode)

	deps := newTestDeps()
	deps.Gateway = newPublicGateway(t)
	r := New(deps)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/t/no-such-tool/", nil))
	// 404 (not 401) proves the gateway route is registered publicly and that
	// the gateway, not the auth middleware, decided the outcome.
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /t/no-such-tool/ status = %d, want 404", rec.Code)
	}
}

func TestActivityRouteRequiresAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := New(newTestDeps())

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/activity", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /admin/activity status = %d, want 401", rec.Code)
	}
}

func TestHealthRouteRequiresAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := New(newTestDeps())

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/health", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /admin/health status = %d, want 401", rec.Code)
	}
}
