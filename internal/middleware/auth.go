// Package middleware provides Gin middleware for authentication, CSRF
// protection, and related cross-cutting concerns. Middleware never trusts
// client-supplied identity (headers, query params); identity is derived solely
// from a server-validated session.
package middleware

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/winduputra/MyCorePlat/internal/model"
	"github.com/winduputra/MyCorePlat/internal/service"
)

// SessionCookieName is the cookie holding the admin session token.
const SessionCookieName = "bpbj_admin_session"

// Context keys for values injected by RequireAuth.
const (
	contextAdminID = "auth_admin_id"
	contextSession = "auth_session"
)

// SessionValidator validates a plaintext session token and returns the live
// session. It is satisfied by *service.SessionService.
type SessionValidator interface {
	Validate(ctx context.Context, plaintextToken string) (*model.AdminSession, error)
}

// RequireAuth returns middleware that rejects any request lacking a valid admin
// session. On success it stores the admin id and session in the Gin context so
// downstream handlers never need to re-read the cookie. On failure it responds
// 401 and aborts, always failing closed.
func RequireAuth(validator SessionValidator, cookieName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := c.Cookie(cookieName)
		if err != nil || token == "" {
			abortUnauthorized(c)
			return
		}

		session, err := validator.Validate(c.Request.Context(), token)
		if err != nil || session == nil {
			abortUnauthorized(c)
			return
		}

		c.Set(contextAdminID, session.AdminID)
		c.Set(contextSession, session)
		c.Next()
	}
}

// abortUnauthorized responds 401 and stops the chain. The message is generic on
// purpose: it must not reveal whether the failure was missing, expired, or
// revoked.
func abortUnauthorized(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
}

// AdminIDFromContext extracts the authenticated admin id injected by
// RequireAuth.
func AdminIDFromContext(c *gin.Context) (uint64, bool) {
	v, ok := c.Get(contextAdminID)
	if !ok {
		return 0, false
	}
	id, ok := v.(uint64)
	return id, ok
}

// SessionFromContext extracts the validated session injected by RequireAuth.
func SessionFromContext(c *gin.Context) (*model.AdminSession, bool) {
	v, ok := c.Get(contextSession)
	if !ok {
		return nil, false
	}
	s, ok := v.(*model.AdminSession)
	return s, ok
}

// Ensure *service.SessionService satisfies SessionValidator at compile time.
var _ SessionValidator = (*service.SessionService)(nil)
