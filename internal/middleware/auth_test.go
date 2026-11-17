package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/winduputra/MyCorePlat/internal/model"
	"github.com/winduputra/MyCorePlat/internal/service"
)

// fakeValidator is a minimal SessionValidator for middleware unit tests.
type fakeValidator struct {
	sessions map[string]*model.AdminSession // keyed by plaintext token
	err      error
}

func (f *fakeValidator) Validate(_ context.Context, plaintext string) (*model.AdminSession, error) {
	if f.err != nil {
		return nil, f.err
	}
	s, ok := f.sessions[plaintext]
	if !ok {
		return nil, service.ErrSessionNotFound
	}
	return s, nil
}

func init() {
	gin.SetMode(gin.TestMode)
}

func newTestContext(method, path string) (*gin.Context, *httptest.ResponseRecorder) {
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(method, path, nil)
	return c, rec
}

// TestRequireAuthRejectsWithoutCookie asserts a request with no session cookie
// is rejected with 401 and the handler chain is not reached.
func TestRequireAuthRejectsWithoutCookie(t *testing.T) {
	v := &fakeValidator{sessions: map[string]*model.AdminSession{}}
	mw := RequireAuth(v, SessionCookieName)

	c, rec := newTestContext(http.MethodGet, "/admin")
	reached := false
	c.Set("should_not_run", false)
	handler := func(gc *gin.Context) { reached = true }

	mw(c)
	if !c.IsAborted() {
		t.Fatal("RequireAuth did not abort the request without a cookie")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	_ = handler
	if reached {
		t.Fatal("downstream handler ran despite missing auth")
	}
}

// TestRequireAuthRejectsInvalidCookie asserts an unknown/expired/revoked token
// (validator returns error) is rejected.
func TestRequireAuthRejectsInvalidCookie(t *testing.T) {
	v := &fakeValidator{err: service.ErrSessionExpired}
	mw := RequireAuth(v, SessionCookieName)

	c, rec := newTestContext(http.MethodGet, "/admin")
	c.Request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "stale"})

	mw(c)
	if !c.IsAborted() {
		t.Fatal("RequireAuth did not abort for an invalid session")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestRequireAuthAcceptsValidCookie asserts a valid session is accepted, the
// handler chain proceeds, and the admin id + session are injected into context.
func TestRequireAuthAcceptsValidCookie(t *testing.T) {
	session := &model.AdminSession{ID: 99, AdminID: 7, ExpiresAt: time.Now().Add(time.Hour)}
	v := &fakeValidator{sessions: map[string]*model.AdminSession{"good-token": session}}
	mw := RequireAuth(v, SessionCookieName)

	c, _ := newTestContext(http.MethodGet, "/admin")
	c.Request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "good-token"})

	mw(c)
	if c.IsAborted() {
		t.Fatal("RequireAuth aborted a valid request")
	}
	adminID, ok := AdminIDFromContext(c)
	if !ok || adminID != 7 {
		t.Fatalf("admin id from context = %d (ok=%v), want 7", adminID, ok)
	}
	got, ok := SessionFromContext(c)
	if !ok || got.ID != 99 {
		t.Fatalf("session from context id = %d (ok=%v), want 99", got.ID, ok)
	}
}

// TestRequireAuthIgnoresSpoofedHeader asserts the identity comes ONLY from the
// validated session cookie, never from client-supplied headers.
func TestRequireAuthIgnoresSpoofedHeader(t *testing.T) {
	v := &fakeValidator{sessions: map[string]*model.AdminSession{}}
	mw := RequireAuth(v, SessionCookieName)

	c, rec := newTestContext(http.MethodGet, "/admin")
	c.Request.Header.Set("X-Admin-Id", "1")
	c.Request.Header.Set("X-Admin", "true")

	mw(c)
	if !c.IsAborted() {
		t.Fatal("RequireAuth trusted a spoofed identity header")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestRequireAuthRejectsNilAdminSession guards against a validator returning
// (nil, nil), which must not be treated as authenticated.
func TestRequireAuthRejectsNilAdminSession(t *testing.T) {
	v := &fakeValidator{sessions: map[string]*model.AdminSession{"tok": nil}}
	mw := RequireAuth(v, SessionCookieName)

	c, rec := newTestContext(http.MethodGet, "/admin")
	c.Request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "tok"})

	mw(c)
	if !c.IsAborted() {
		t.Fatal("RequireAuth accepted a nil session")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestRequireAuthPropagatesValidatorError confirms internal errors still result
// in rejection (fail closed), not a 500 leak of details.
func TestRequireAuthPropagatesValidatorError(t *testing.T) {
	v := &fakeValidator{err: errors.New("db down")}
	mw := RequireAuth(v, SessionCookieName)

	c, rec := newTestContext(http.MethodGet, "/admin")
	c.Request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "tok"})

	mw(c)
	if !c.IsAborted() {
		t.Fatal("RequireAuth did not fail closed on validator error")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}
