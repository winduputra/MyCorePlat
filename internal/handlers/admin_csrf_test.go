package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/winduputra/MyCorePlat/internal/model"
)

// renderSessionToken is a fixed CSRF token injected into the gin context so the
// admin handlers can populate their view models during rendering.
const renderSessionToken = "render-csrf-token-xyz789"

// sessionInjector mirrors what RequireAuth does on success: it puts a validated
// session (carrying the CSRF token) into the gin context so handlers can read it.
func sessionInjector() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("auth_admin_id", uint64(1))
		c.Set("auth_session", &model.AdminSession{ID: 1, AdminID: 1, CSRFToken: renderSessionToken})
		c.Next()
	}
}

// containsCSRFInput reports whether the body includes a hidden csrf_token input.
func containsCSRFInput(body string) bool {
	return strings.Contains(body, `name="csrf_token"`) && strings.Contains(body, `type="hidden"`)
}

// TestToolFormRendersCSRFHiddenInput asserts the create/edit tool form carries a
// hidden csrf_token field populated from the session, so a browser POST succeeds.
func TestToolFormRendersCSRFHiddenInput(t *testing.T) {
	h := newToolsHandler(t, newFakeToolService())
	r := gin.New()
	r.Use(sessionInjector())
	r.GET("/admin/tools/new", h.New)

	req := httptest.NewRequest(http.MethodGet, "/admin/tools/new", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !containsCSRFInput(body) {
		t.Errorf("tool form missing hidden csrf_token input")
	}
	if !strings.Contains(body, renderSessionToken) {
		t.Errorf("tool form does not contain the session CSRF token")
	}
}

// TestTokenCreateRendersCSRFHiddenInput asserts the token create form carries the
// hidden csrf_token field.
func TestTokenCreateRendersCSRFHiddenInput(t *testing.T) {
	h := newTokensHandler(t, newFakeTokenService(), tokenFixtureTool())
	r := gin.New()
	r.Use(sessionInjector())
	r.GET("/admin/tools/:id/tokens/new", h.New)

	req := httptest.NewRequest(http.MethodGet, "/admin/tools/5/tokens/new", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !containsCSRFInput(body) || !strings.Contains(body, renderSessionToken) {
		t.Errorf("token create form missing hidden csrf_token field with session token")
	}
}

// TestLayoutRendersHTMXCSRFHeader asserts the layout body carries the HTMX
// hx-headers attribute with the CSRF token, which covers the HTMX delete-tool and
// revoke-token buttons.
func TestLayoutRendersHTMXCSRFHeader(t *testing.T) {
	h := newToolsHandler(t, newFakeToolService())
	r := gin.New()
	r.Use(sessionInjector())
	r.GET("/admin/tools", h.List)

	req := httptest.NewRequest(http.MethodGet, "/admin/tools", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "hx-headers") {
		t.Errorf("layout body missing hx-headers attribute")
	}
	if !strings.Contains(body, "X-CSRF-Token") || !strings.Contains(body, renderSessionToken) {
		t.Errorf("layout hx-headers missing X-CSRF-Token with session token")
	}
}

// TestLogoutFormRendersCSRFHiddenInput asserts the logout form in the layout
// carries the hidden csrf_token field.
func TestLogoutFormRendersCSRFHiddenInput(t *testing.T) {
	h := newToolsHandler(t, newFakeToolService())
	r := gin.New()
	r.Use(sessionInjector())
	r.GET("/admin/tools", h.List)

	req := httptest.NewRequest(http.MethodGet, "/admin/tools", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	body := w.Body.String()
	if !containsCSRFInput(body) {
		t.Errorf("logout form missing hidden csrf_token input")
	}
}

// TestCSRFTokenNotInQueryString asserts the rendered admin page never embeds the
// CSRF token in a URL (it must only ride inside form fields / headers).
func TestCSRFTokenNotInQueryString(t *testing.T) {
	h := newToolsHandler(t, newFakeToolService())
	r := gin.New()
	r.Use(sessionInjector())
	r.GET("/admin/tools", h.List)

	req := httptest.NewRequest(http.MethodGet, "/admin/tools", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	body := w.Body.String()
	if strings.Contains(body, "csrf_token="+renderSessionToken) {
		t.Errorf("CSRF token leaked into a query string")
	}
	if strings.Contains(body, "?csrf=") || strings.Contains(body, "&csrf=") {
		t.Errorf("CSRF token appears as a query parameter")
	}
}
