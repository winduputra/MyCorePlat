package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/winduputra/MyCorePlat/internal/middleware"
	"github.com/winduputra/MyCorePlat/internal/model"
)

// csrfSessionToken is the CSRF token the stub validator attaches to every
// session, so tests can present a matching or mismatching token.
const csrfSessionToken = "csrf-session-token-abc123"

// csrfValidator returns a live session carrying csrfSessionToken, so RequireAuth
// succeeds and RequireCSRF has a real token to compare against. It stands in for
// *service.SessionService without touching the database.
type csrfValidator struct{}

func (csrfValidator) Validate(_ context.Context, _ string) (*model.AdminSession, error) {
	return &model.AdminSession{ID: 7, AdminID: 3, CSRFToken: csrfSessionToken}, nil
}

// csrfTestRouter builds the real router (real RequireAuth + RequireCSRF) with
// stub services, so CSRF enforcement is exercised end to end rather than mocked.
func csrfTestRouter() *gin.Engine {
	deps := newTestDeps()
	deps.SessionValidator = csrfValidator{}
	return New(deps)
}

// csrfRequest issues an authenticated POST with a session cookie so RequireAuth
// passes, and optionally attaches a CSRF token via the header or form field.
func csrfRequest(t *testing.T, r *gin.Engine, path, headerToken, formToken string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{}
	if formToken != "" {
		form.Set("csrf_token", formToken)
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "bpbj_admin_session", Value: "live-session"})
	if headerToken != "" {
		req.Header.Set(middleware.CSRFHeaderName, headerToken)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// The mutation endpoints under the protected admin group. Every one must reject
// a missing or wrong CSRF token with 403 and admit a valid one.
var csrfMutationPaths = []string{
	"/admin/logout",
	"/admin/tools",
	"/admin/tools/5",
	"/admin/tools/5/delete",
	"/admin/tools/5/tokens",
	"/admin/tools/5/tokens/9/revoke",
}

// TestCSRFMutationsRejectMissingToken asserts that every admin mutation without a
// CSRF token is rejected with 403 (fail closed), even with a valid session.
func TestCSRFMutationsRejectMissingToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := csrfTestRouter()

	for _, path := range csrfMutationPaths {
		rec := csrfRequest(t, r, path, "", "")
		if rec.Code != http.StatusForbidden {
			t.Fatalf("POST %s without CSRF token: status = %d, want 403", path, rec.Code)
		}
	}
}

// TestCSRFMutationsRejectInvalidToken asserts that a wrong token is rejected with
// 403 for every mutation.
func TestCSRFMutationsRejectInvalidToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := csrfTestRouter()

	for _, path := range csrfMutationPaths {
		rec := csrfRequest(t, r, path, "not-the-right-token", "")
		if rec.Code != http.StatusForbidden {
			t.Fatalf("POST %s with invalid CSRF token: status = %d, want 403", path, rec.Code)
		}
	}
}

// TestCSRFMutationsAcceptHeaderToken asserts the X-CSRF-Token header (used by
// HTMX) passes the CSRF gate for every mutation; the request is then handled by
// the service layer (any status other than 403 proves the gate was cleared).
func TestCSRFMutationsAcceptHeaderToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := csrfTestRouter()

	for _, path := range csrfMutationPaths {
		rec := csrfRequest(t, r, path, csrfSessionToken, "")
		if rec.Code == http.StatusForbidden {
			t.Fatalf("POST %s with valid X-CSRF-Token header: status = 403, want CSRF gate to pass", path)
		}
	}
}

// TestCSRFMutationsAcceptFormToken asserts the hidden csrf_token form field
// (used by the plain HTML forms) passes the CSRF gate for every mutation.
func TestCSRFMutationsAcceptFormToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := csrfTestRouter()

	for _, path := range csrfMutationPaths {
		rec := csrfRequest(t, r, path, "", csrfSessionToken)
		if rec.Code == http.StatusForbidden {
			t.Fatalf("POST %s with valid csrf_token form field: status = 403, want CSRF gate to pass", path)
		}
	}
}

// TestCSRFStillRequiresAuthentication asserts the CSRF layer never weakens the
// session requirement: without a session cookie the request is 401, not 403, and
// a valid CSRF token cannot substitute for authentication.
func TestCSRFStillRequiresAuthentication(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := csrfTestRouter()

	// No session cookie, but a valid CSRF token in the header.
	req := httptest.NewRequest(http.MethodPost, "/admin/logout", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(middleware.CSRFHeaderName, csrfSessionToken)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("POST /admin/logout without session: status = %d, want 401", rec.Code)
	}
}
