package middleware

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/winduputra/MyCorePlat/internal/model"
)

func contextWithSession(c *gin.Context, csrf string) {
	session := &model.AdminSession{ID: 1, AdminID: 1, CSRFToken: csrf, ExpiresAt: time.Now().Add(time.Hour)}
	c.Set(contextSession, session)
	c.Set(contextAdminID, session.AdminID)
}

// TestCSRFAllowsSafeMethods asserts GET/HEAD/OPTIONS bypass CSRF checks.
func TestCSRFAllowsSafeMethods(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		c, _ := newTestContext(method, "/admin")
		contextWithSession(c, "csrf-abc")
		mw := RequireCSRF()
		mw(c)
		if c.IsAborted() {
			t.Fatalf("%s was blocked by CSRF middleware", method)
		}
	}
}

// TestCSRFRejectsMissingToken asserts a state-changing request without a token
// is rejected with 403.
func TestCSRFRejectsMissingToken(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		c, rec := newTestContext(method, "/admin")
		contextWithSession(c, "csrf-abc")
		mw := RequireCSRF()
		mw(c)
		if !c.IsAborted() {
			t.Fatalf("%s without CSRF token was not blocked", method)
		}
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s status = %d, want 403", method, rec.Code)
		}
	}
}

// TestCSRFRejectsInvalidToken asserts a mismatched token is rejected.
func TestCSRFRejectsInvalidToken(t *testing.T) {
	c, rec := newTestContext(http.MethodPost, "/admin")
	contextWithSession(c, "csrf-abc")
	c.Request.Header.Set("X-CSRF-Token", "wrong")

	mw := RequireCSRF()
	mw(c)
	if !c.IsAborted() {
		t.Fatal("CSRF middleware accepted an invalid token")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

// TestCSRFAcceptsHeaderToken asserts a valid token in the X-CSRF-Token header
// (used by HTMX) is accepted.
func TestCSRFAcceptsHeaderToken(t *testing.T) {
	c, _ := newTestContext(http.MethodPost, "/admin")
	contextWithSession(c, "csrf-abc")
	c.Request.Header.Set("X-CSRF-Token", "csrf-abc")

	mw := RequireCSRF()
	mw(c)
	if c.IsAborted() {
		t.Fatal("CSRF middleware rejected a valid header token")
	}
}

// TestCSRFAcceptsFormToken asserts a valid token in the form field is accepted.
func TestCSRFAcceptsFormToken(t *testing.T) {
	c, _ := newTestContext(http.MethodPost, "/admin")
	contextWithSession(c, "csrf-abc")
	c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.Request.Body = io.NopCloser(strings.NewReader("csrf_token=csrf-abc"))

	mw := RequireCSRF()
	mw(c)
	if c.IsAborted() {
		t.Fatal("CSRF middleware rejected a valid form token")
	}
}

// TestCSRFRejectsWhenNoSession asserts that CSRF cannot pass without an
// authenticated session in context (defense in depth: CSRF runs after auth).
func TestCSRFRejectsWhenNoSession(t *testing.T) {
	c, rec := newTestContext(http.MethodPost, "/admin")
	c.Request.Header.Set("X-CSRF-Token", "csrf-abc")

	mw := RequireCSRF()
	mw(c)
	if !c.IsAborted() {
		t.Fatal("CSRF middleware passed with no session in context")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}
