package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/winduputra/MyCorePlat/internal/model"
	"github.com/winduputra/MyCorePlat/internal/service"
)

type fakeAuthService struct {
	loginErr    error
	plaintext   string
	session     *model.AdminSession
	admin       *model.Admin
	loginCalls  int
	logoutErr   error
	logoutCalls int
	capturedU   string
}

func (f *fakeAuthService) Login(_ context.Context, username, _ string, _ service.SessionMeta) (string, *model.AdminSession, error) {
	f.loginCalls++
	f.capturedU = username
	if f.loginErr != nil {
		return "", nil, f.loginErr
	}
	s := f.session
	if s == nil {
		s = &model.AdminSession{ID: 10, CSRFToken: "csrf-token"}
	}
	return f.plaintext, s, nil
}

func (f *fakeAuthService) Logout(_ context.Context, _ uint64) error {
	f.logoutCalls++
	return f.logoutErr
}

func newAuthTestRouter(h *AuthHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/admin/login", h.LoginPage)
	r.POST("/admin/login", h.LoginSubmit)
	r.POST("/admin/logout", h.Logout)
	return r
}

func postForm(t *testing.T, r *gin.Engine, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// TestLoginSubmitSetsHardenedCookie asserts a successful login sets the
// session cookie with HttpOnly and SameSite=Lax (Secure when configured).
func TestLoginSubmitSetsHardenedCookie(t *testing.T) {
	fake := &fakeAuthService{
		plaintext: "plaintext-token",
		session:   &model.AdminSession{ID: 1, CSRFToken: "csrf"},
	}
	h := NewAuthHandler(fake, nil, AuthOptions{
		CookieName:   "bpbj_admin_session",
		CookieSecure: true,
		CookiePath:   "/",
		SessionTTL:   3600,
	})
	r := newAuthTestRouter(h)

	w := postForm(t, r, "/admin/login", url.Values{"username": {"alice"}, "password": {"secret"}})
	if w.Code != http.StatusSeeOther && w.Code != http.StatusFound {
		t.Fatalf("status = %d, want redirect 303/302", w.Code)
	}
	cookies := w.Result().Cookies()
	var session *http.Cookie
	for _, c := range cookies {
		if c.Name == "bpbj_admin_session" {
			session = c
		}
	}
	if session == nil {
		t.Fatal("session cookie was not set")
	}
	if session.Value != "plaintext-token" {
		t.Fatalf("cookie value = %q, want plaintext token", session.Value)
	}
	if !session.HttpOnly {
		t.Fatal("session cookie is not HttpOnly")
	}
	if !session.Secure {
		t.Fatal("session cookie is not Secure in secure mode")
	}
	if session.SameSite != http.SameSiteLaxMode {
		t.Fatalf("SameSite = %v, want Lax", session.SameSite)
	}
	if fake.loginCalls != 1 {
		t.Fatalf("Login called %d times, want 1", fake.loginCalls)
	}
}

// TestLoginSubmitCookieNotSecureInDev asserts Secure is off when not configured.
func TestLoginSubmitCookieNotSecureInDev(t *testing.T) {
	fake := &fakeAuthService{plaintext: "tok", session: &model.AdminSession{ID: 1}}
	h := NewAuthHandler(fake, nil, AuthOptions{CookieName: "bpbj_admin_session", CookieSecure: false, CookiePath: "/", SessionTTL: 3600})
	r := newAuthTestRouter(h)

	w := postForm(t, r, "/admin/login", url.Values{"username": {"alice"}, "password": {"secret"}})
	for _, c := range w.Result().Cookies() {
		if c.Name == "bpbj_admin_session" && c.Secure {
			t.Fatal("Secure flag should be off in non-secure mode")
		}
	}
}

// TestLoginSubmitRejectsBadCredentials asserts a generic error and no cookie.
func TestLoginSubmitRejectsBadCredentials(t *testing.T) {
	fake := &fakeAuthService{loginErr: service.ErrInvalidCredentials}
	h := NewAuthHandler(fake, nil, AuthOptions{CookieName: "bpbj_admin_session", CookiePath: "/", SessionTTL: 3600})
	r := newAuthTestRouter(h)

	w := postForm(t, r, "/admin/login", url.Values{"username": {"alice"}, "password": {"wrong"}})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if strings.Contains(w.Body.String(), "wrong") || strings.Contains(strings.ToLower(w.Body.String()), "password") {
		t.Fatal("error response leaked credential detail")
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == "bpbj_admin_session" {
			t.Fatal("session cookie must not be set on failed login")
		}
	}
}

// TestLoginSubmitRejectsEmptyInput asserts empty fields do not call the service.
func TestLoginSubmitRejectsEmptyInput(t *testing.T) {
	fake := &fakeAuthService{}
	h := NewAuthHandler(fake, nil, AuthOptions{CookieName: "bpbj_admin_session", CookiePath: "/", SessionTTL: 3600})
	r := newAuthTestRouter(h)

	w := postForm(t, r, "/admin/login", url.Values{"username": {""}, "password": {""}})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if fake.loginCalls != 0 {
		t.Fatal("service must not be called for empty input")
	}
}

// TestLogoutClearsCookie asserts logout revokes the session and clears the cookie.
func TestLogoutClearsCookie(t *testing.T) {
	fake := &fakeAuthService{}
	h := NewAuthHandler(fake, nil, AuthOptions{CookieName: "bpbj_admin_session", CookiePath: "/", SessionTTL: 3600})

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/admin/logout", func(c *gin.Context) {
		c.Set("auth_session", &model.AdminSession{ID: 55})
		h.Logout(c)
	})

	w := postForm(t, r, "/admin/logout", url.Values{})
	if w.Code != http.StatusSeeOther && w.Code != http.StatusFound {
		t.Fatalf("status = %d, want redirect", w.Code)
	}
	var found bool
	for _, c := range w.Result().Cookies() {
		if c.Name == "bpbj_admin_session" {
			found = true
			if c.MaxAge >= 0 && c.Value == "plaintext-token" {
				t.Fatal("cookie not cleared on logout")
			}
		}
	}
	if !found {
		t.Fatal("logout did not clear the session cookie")
	}
	if fake.logoutCalls != 1 {
		t.Fatalf("Logout called %d times, want 1", fake.logoutCalls)
	}
}

// TestLoginPageRenders ensures the login page returns 200 HTML.
func TestLoginPageRenders(t *testing.T) {
	h := NewAuthHandler(&fakeAuthService{}, nil, AuthOptions{CookieName: "bpbj_admin_session", CookiePath: "/", SessionTTL: 3600})
	r := newAuthTestRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/admin/login", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "form") {
		t.Fatal("login page did not render a form")
	}
}

var _ = errors.Is

// fakePreAuthIssuer returns a fixed token so tests can assert rendering and
// cookie behavior deterministically.
type fakePreAuthIssuer struct {
	token    string
	err      error
	issueCnt int
}

func (f *fakePreAuthIssuer) Issue() (string, time.Time, error) {
	f.issueCnt++
	if f.err != nil {
		return "", time.Time{}, f.err
	}
	return f.token, time.Now().Add(10 * time.Minute), nil
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// TestLoginPageIssuesPreAuthCookie asserts GET /admin/login sets the pre-auth
// CSRF cookie with the required flags and embeds the token in the form.
func TestLoginPageIssuesPreAuthCookie(t *testing.T) {
	issuer := &fakePreAuthIssuer{token: "issued-token-123"}
	h := NewAuthHandler(&fakeAuthService{}, issuer, AuthOptions{
		CookieName:     "bpbj_admin_session",
		CookieSecure:   true,
		CookiePath:     "/",
		SessionTTL:     3600,
		PreAuthCSRFTTL: 600,
	})
	r := newAuthTestRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/admin/login", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	cookie := findCookie(w.Result().Cookies(), preAuthCSRFCookieName)
	if cookie == nil {
		t.Fatal("pre-auth CSRF cookie was not set")
	}
	if cookie.Value != "issued-token-123" {
		t.Fatalf("cookie value = %q, want issued token", cookie.Value)
	}
	if !cookie.HttpOnly {
		t.Fatal("pre-auth cookie must be HttpOnly")
	}
	if !cookie.Secure {
		t.Fatal("pre-auth cookie must be Secure when configured")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("pre-auth SameSite = %v, want Lax", cookie.SameSite)
	}
	if cookie.Path != "/admin" {
		t.Fatalf("pre-auth cookie path = %q, want /admin", cookie.Path)
	}
	if cookie.MaxAge <= 0 || cookie.MaxAge > 600 {
		t.Fatalf("pre-auth cookie MaxAge = %d, want in (0,600]", cookie.MaxAge)
	}
	if !strings.Contains(w.Body.String(), "issued-token-123") {
		t.Fatal("login form does not embed the pre-auth token")
	}
	if !strings.Contains(w.Body.String(), `name="csrf_token"`) {
		t.Fatal("login form lacks the csrf_token hidden field")
	}
}

// TestLoginPageFailsWhenIssuerErrors asserts a failed token issue does not
// render a form without protection.
func TestLoginPageFailsWhenIssuerErrors(t *testing.T) {
	issuer := &fakePreAuthIssuer{err: errors.New("boom")}
	h := NewAuthHandler(&fakeAuthService{}, issuer, AuthOptions{CookieName: "c", CookiePath: "/", SessionTTL: 3600})
	r := newAuthTestRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/admin/login", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 when token issuance fails", w.Code)
	}
}

// TestLoginSubmitClearsPreAuthCookie asserts the pre-auth cookie is expired
// after a successful authentication.
func TestLoginSubmitClearsPreAuthCookie(t *testing.T) {
	fake := &fakeAuthService{plaintext: "tok", session: &model.AdminSession{ID: 1}}
	h := NewAuthHandler(fake, &fakePreAuthIssuer{token: "t"}, AuthOptions{
		CookieName: "bpbj_admin_session", CookiePath: "/", SessionTTL: 3600, PreAuthCSRFTTL: 600,
	})
	r := newAuthTestRouter(h)

	w := postForm(t, r, "/admin/login", url.Values{"username": {"alice"}, "password": {"secret"}})
	cookie := findCookie(w.Result().Cookies(), preAuthCSRFCookieName)
	if cookie == nil {
		t.Fatal("login response did not clear the pre-auth cookie")
	}
	if cookie.Value != "" || cookie.MaxAge >= 0 {
		t.Fatalf("pre-auth cookie not expired: value=%q maxAge=%d", cookie.Value, cookie.MaxAge)
	}
}
