package middleware

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

const testLoginCSRFSecret = "unit-test-preauth-csrf-secret"

func newLoginCSRFService(t *testing.T, ttl time.Duration) *service.PreAuthCSRFService {
	t.Helper()
	return service.NewPreAuthCSRFService([]byte(testLoginCSRFSecret), ttl)
}

// loginCSRFContext builds a gin test context for a POST /admin/login carrying
// the given pre-auth cookie value and form/header token (empty means absent).
func loginCSRFContext(cookieVal, formToken, headerToken string) *gin.Context {
	gin.SetMode(gin.TestMode)
	form := url.Values{}
	form.Set("username", "admin")
	form.Set("password", "secret")
	if formToken != "" {
		form.Set(preAuthCSRFFormField, formToken)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if headerToken != "" {
		req.Header.Set(CSRFHeaderName, headerToken)
	}
	if cookieVal != "" {
		req.AddCookie(&http.Cookie{Name: PreAuthCSRFCookieName, Value: cookieVal})
	}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	return c
}

func runLoginCSRF(c *gin.Context, mw gin.HandlerFunc) {
	mw(c)
}

func TestLoginCSRFRejectsWithoutCookie(t *testing.T) {
	svc := newLoginCSRFService(t, 10*time.Minute)
	token, _, _ := svc.Issue()
	c := loginCSRFContext("", token, "")
	runLoginCSRF(c, RequireLoginCSRF(svc, ""))
	if c.Writer.Status() != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", c.Writer.Status())
	}
}

func TestLoginCSRFRejectsWithoutFormToken(t *testing.T) {
	svc := newLoginCSRFService(t, 10*time.Minute)
	token, _, _ := svc.Issue()
	c := loginCSRFContext(token, "", "")
	runLoginCSRF(c, RequireLoginCSRF(svc, ""))
	if c.Writer.Status() != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", c.Writer.Status())
	}
}

func TestLoginCSRFRejectsTokenMismatch(t *testing.T) {
	svc := newLoginCSRFService(t, 10*time.Minute)
	cookieToken, _, _ := svc.Issue()
	formToken, _, _ := svc.Issue()
	c := loginCSRFContext(cookieToken, formToken, "")
	runLoginCSRF(c, RequireLoginCSRF(svc, ""))
	if c.Writer.Status() != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", c.Writer.Status())
	}
}

func TestLoginCSRFRejectsAttackerManipulatedCookie(t *testing.T) {
	svc := newLoginCSRFService(t, 10*time.Minute)
	attacker := service.NewPreAuthCSRFService([]byte("attacker-secret"), 10*time.Minute)
	forged, _, _ := attacker.Issue()
	c := loginCSRFContext(forged, forged, "")
	runLoginCSRF(c, RequireLoginCSRF(svc, ""))
	if c.Writer.Status() != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for forged HMAC", c.Writer.Status())
	}
}

func TestLoginCSRFRejectsTamperedCookie(t *testing.T) {
	svc := newLoginCSRFService(t, 10*time.Minute)
	token, _, _ := svc.Issue()
	tampered := token[:len(token)-1] + "X"
	c := loginCSRFContext(tampered, tampered, "")
	runLoginCSRF(c, RequireLoginCSRF(svc, ""))
	if c.Writer.Status() != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for tampered token", c.Writer.Status())
	}
}

func TestLoginCSRFAcceptsValidPair(t *testing.T) {
	svc := newLoginCSRFService(t, 10*time.Minute)
	token, _, _ := svc.Issue()
	c := loginCSRFContext(token, token, "")
	runLoginCSRF(c, RequireLoginCSRF(svc, ""))
	if c.Writer.Status() == http.StatusForbidden {
		t.Fatal("valid CSRF pair was rejected")
	}
	if c.IsAborted() {
		t.Fatal("valid CSRF pair aborted the chain")
	}
}

func TestLoginCSRFRejectsExpiredToken(t *testing.T) {
	svc := newLoginCSRFService(t, 0) // already expired
	token, _, _ := svc.Issue()
	c := loginCSRFContext(token, token, "")
	runLoginCSRF(c, RequireLoginCSRF(svc, ""))
	if c.Writer.Status() != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for expired token", c.Writer.Status())
	}
}

func TestLoginCSRFHeaderTokenAccepted(t *testing.T) {
	svc := newLoginCSRFService(t, 10*time.Minute)
	token, _, _ := svc.Issue()
	c := loginCSRFContext(token, "", token) // header instead of form
	runLoginCSRF(c, RequireLoginCSRF(svc, ""))
	if c.Writer.Status() == http.StatusForbidden {
		t.Fatal("valid header-supplied token was rejected")
	}
}

func TestLoginCSRFSkipsSafeMethods(t *testing.T) {
	svc := newLoginCSRFService(t, 10*time.Minute)
	gin.SetMode(gin.TestMode)
	req := httptest.NewRequest(http.MethodGet, "/admin/login", nil)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	runLoginCSRF(c, RequireLoginCSRF(svc, ""))
	if c.Writer.Status() == http.StatusForbidden {
		t.Fatal("GET must not require a pre-auth CSRF token")
	}
}

func TestLoginCSRFFailsClosedWithoutService(t *testing.T) {
	c := loginCSRFContext("anything", "anything", "")
	runLoginCSRF(c, RequireLoginCSRF(nil, ""))
	if c.Writer.Status() != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 when verifier is nil", c.Writer.Status())
	}
}
