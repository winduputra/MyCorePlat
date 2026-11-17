package handlers

import (
	"github.com/gin-gonic/gin"

	"github.com/winduputra/MyCorePlat/internal/middleware"
)

// csrfToken returns the CSRF token bound to the current admin session so admin
// pages can embed it in their POST forms and HTMX requests. It returns an empty
// string when no session is present; the CSRF middleware rejects such requests,
// so an empty token simply means "no mutation will be accepted".
//
// The token is taken from the server-side session (never from the request), so
// it cannot be influenced by the client.
func csrfToken(c *gin.Context) string {
	if session, ok := middleware.SessionFromContext(c); ok && session != nil {
		return session.CSRFToken
	}
	return ""
}

// csrfCarrier is implemented by admin page view models that expose a CSRF token
// to their template. Render helpers populate it centrally so every handler does
// not need to remember.
type csrfCarrier interface {
	setCSRFToken(token string)
}

// withCSRF sets the session CSRF token on any admin view model passed to a
// render helper. Callers pass value literals, so the function copies the value
// into an addressable local, sets the token, and returns a pointer to it for
// template execution. Non-carrier values are returned unchanged.
func withCSRF(c *gin.Context, data any) any {
	token := csrfToken(c)
	switch d := data.(type) {
	case toolListData:
		d.setCSRFToken(token)
		return &d
	case toolFormData:
		d.setCSRFToken(token)
		return &d
	case tokenListData:
		d.setCSRFToken(token)
		return &d
	case tokenCreateData:
		d.setCSRFToken(token)
		return &d
	case activityListData:
		d.setCSRFToken(token)
		return &d
	case healthListData:
		d.setCSRFToken(token)
		return &d
	case installerListData:
		d.setCSRFToken(token)
		return &d
	default:
		return data
	}
}
