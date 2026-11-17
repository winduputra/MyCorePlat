package middleware

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/winduputra/MyCorePlat/internal/service"
)

// Pre-auth CSRF cookie issued on GET /admin/login and consumed on
// POST /admin/login. It is deliberately scoped to /admin so it is not sent on
// unrelated requests.
const (
	PreAuthCSRFCookieName = "bpbj_login_csrf"
	preAuthCSRFFormField  = "csrf_token"
)

// LoginCSRFVerifier verifies a signed pre-auth CSRF token.
type LoginCSRFVerifier interface {
	Verify(token string) error
}

// RequireLoginCSRF protects the pre-authentication login POST. Because no
// session exists yet, it uses a signed double-submit cookie: the token placed
// in the HttpOnly cookie MUST equal the token supplied in the form field (or
// the X-CSRF-Token header), and the token's HMAC signature MUST be valid.
//
// SameSite=Lax alone does not stop a cross-site top-level form POST, which is
// why this explicit pre-auth token is required. trustedOrigin, when non-empty,
// enables an additional Origin/Referer check on unsafe methods.
func RequireLoginCSRF(verifier LoginCSRFVerifier, trustedOrigin string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if isSafeMethod(c.Request.Method) {
			c.Next()
			return
		}

		if verifier == nil {
			abortLoginCSRF(c)
			return
		}

		// Defense in depth: reject obviously cross-origin posts when the client
		// sends Origin/Referer and a trusted origin is configured.
		if !originAllowed(c, trustedOrigin) {
			abortLoginCSRF(c)
			return
		}

		cookieToken, err := c.Cookie(PreAuthCSRFCookieName)
		if err != nil || cookieToken == "" {
			abortLoginCSRF(c)
			return
		}

		supplied := c.GetHeader(CSRFHeaderName)
		if supplied == "" {
			supplied = c.PostForm(preAuthCSRFFormField)
		}
		if supplied == "" {
			abortLoginCSRF(c)
			return
		}

		// Constant-time equality of cookie vs supplied, then HMAC verification.
		if !service.ValidateCSRF(cookieToken, supplied) {
			abortLoginCSRF(c)
			return
		}
		if err := verifier.Verify(cookieToken); err != nil {
			abortLoginCSRF(c)
			return
		}

		c.Next()
	}
}

func abortLoginCSRF(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid or missing CSRF token"})
}

// originAllowed checks Origin (preferred) or Referer against trustedOrigin.
// When trustedOrigin is empty the check is disabled so that local development
// and tests without a configured public origin keep working.
func originAllowed(c *gin.Context, trustedOrigin string) bool {
	if trustedOrigin == "" {
		return true
	}
	if origin := c.GetHeader("Origin"); origin != "" {
		return sameOrigin(origin, trustedOrigin)
	}
	if referer := c.GetHeader("Referer"); referer != "" {
		return sameOrigin(referer, trustedOrigin)
	}
	// No Origin/Referer header: fall back to the token checks rather than
	// rejecting non-browser clients outright.
	return true
}

func sameOrigin(candidate, trusted string) bool {
	candidateHost, err := originHost(candidate)
	if err != nil {
		return false
	}
	trustedHost, err := originHost(trusted)
	if err != nil {
		return false
	}
	return strings.EqualFold(candidateHost, trustedHost)
}

func originHost(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	host := u.Host
	if host == "" {
		// Allow bare hosts like "example.com" for configuration convenience.
		host = u.Path
	}
	return strings.TrimSuffix(host, "/"), nil
}
