package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/winduputra/MyCorePlat/internal/service"
)

// CSRFHeaderName is the header HTMX (and fetch clients) use to send the token.
const CSRFHeaderName = "X-CSRF-Token"

// csrfFormField is the fallback form field name for non-HTMX form posts.
const csrfFormField = "csrf_token"

// RequireCSRF returns middleware that enforces a per-session CSRF token on
// state-changing requests (POST/PUT/PATCH/DELETE). Safe methods pass through.
//
// The expected token comes from the validated session placed in context by
// RequireAuth; it MUST run after RequireAuth. SameSite cookies are treated as
// defense-in-depth only, never as a substitute for this token check.
func RequireCSRF() gin.HandlerFunc {
	return func(c *gin.Context) {
		if isSafeMethod(c.Request.Method) {
			c.Next()
			return
		}

		session, ok := SessionFromContext(c)
		if !ok || session == nil || session.CSRFToken == "" {
			// No authenticated session in context: fail closed.
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid or missing CSRF token"})
			return
		}

		supplied := c.GetHeader(CSRFHeaderName)
		if supplied == "" {
			// Fall back to a form field for plain HTML form posts.
			supplied = c.PostForm(csrfFormField)
		}

		if !service.ValidateCSRF(session.CSRFToken, supplied) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid or missing CSRF token"})
			return
		}
		c.Next()
	}
}

// isSafeMethod reports whether method is CSRF-exempt (read-only).
func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}
