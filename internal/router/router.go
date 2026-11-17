// Package router builds the HTTP router for the Core application.
// It wires routes to handlers and centralizes middleware registration.
package router

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/winduputra/MyCorePlat/internal/gateway"
	"github.com/winduputra/MyCorePlat/internal/handlers"
	"github.com/winduputra/MyCorePlat/internal/middleware"
	"github.com/winduputra/MyCorePlat/internal/service"
)

// Deps are the collaborators the router needs. Passing them explicitly keeps
// the router free of global state and easy to test.
type Deps struct {
	Auth                 *handlers.AuthHandler
	Tools                *handlers.AdminToolsHandler
	Tokens               *handlers.AdminTokensHandler
	Activity             *handlers.AdminActivityHandler
	Health               *handlers.AdminHealthHandler
	Installer            *handlers.AdminInstallerHandler
	Catalog              *handlers.CatalogHandler // public homepage (active+public tools)
	Gateway              *gateway.Gateway
	SessionValidator     middleware.SessionValidator
	SessionCookieName    string
	LoginCSRFVerifier    middleware.LoginCSRFVerifier // protects the pre-auth login POST
	TrustedOrigin        string                       // optional; enables Origin/Referer check on login
	ProtectedHandlerStub gin.HandlerFunc              // placeholder for the admin dashboard (later task)
}

// New constructs the application router.
func New(deps Deps) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/health", handlers.Health)

	// Root landing. For an anonymous visitor this is the public tool catalog
	// (when a catalog handler is wired) so https://<host>/ never returns 404 and
	// shows what is actually usable. An authenticated admin is sent straight to
	// the dashboard, and a visitor with no catalog falls back to the login page.
	// The route is public and only inspects the session cookie — never headers.
	authCheck := func(c *gin.Context) bool {
		if deps.SessionValidator == nil {
			return false
		}
		token, err := c.Cookie(deps.SessionCookieName)
		if err != nil || token == "" {
			return false
		}
		session, err := deps.SessionValidator.Validate(c.Request.Context(), token)
		return err == nil && session != nil
	}

	switch {
	case deps.Catalog != nil:
		r.GET("/", handlers.NewRootHandlerForCatalog(authCheck, deps.Catalog))
	case deps.SessionValidator != nil:
		root := handlers.NewRootHandler(authCheck)
		r.GET("/", root.Serve)
	default:
		r.GET("/", func(c *gin.Context) { c.Redirect(http.StatusFound, "/admin/login") })
	}

	// Public tool gateway. These routes are intentionally outside the admin
	// group: the gateway enforces per-tool status and access type itself, so no
	// admin session is required. Access-type=token tools are rejected inside the
	// gateway until the token lifecycle (Task 10) exists.
	if deps.Gateway != nil {
		r.Any("/t/:slug", deps.Gateway.Serve)
		r.Any("/t/:slug/*path", deps.Gateway.Serve)
	}

	if deps.Auth != nil {
		// GET issues the pre-auth CSRF cookie; POST requires that cookie plus a
		// matching signed token, so a cross-site login POST is rejected.
		r.GET("/admin/login", deps.Auth.LoginPage)
		r.POST("/admin/login",
			middleware.RequireLoginCSRF(deps.LoginCSRFVerifier, deps.TrustedOrigin),
			deps.Auth.LoginSubmit,
		)

		// Protected admin group: every route here requires a valid session and,
		// for state-changing methods, a valid CSRF token.
		admin := r.Group("/admin")
		admin.Use(middleware.RequireAuth(deps.SessionValidator, deps.SessionCookieName))
		admin.Use(middleware.RequireCSRF())
		{
			admin.POST("/logout", deps.Auth.Logout)
			if deps.ProtectedHandlerStub != nil {
				admin.GET("", deps.ProtectedHandlerStub)
			}

			// Tool registry CRUD. GETs need a valid session; POSTs (create,
			// update, delete) additionally require a CSRF token via the group
			// middleware. No public access to any of these routes.
			if deps.Tools != nil {
				admin.GET("/tools", deps.Tools.List)
				admin.GET("/tools/new", deps.Tools.New)
				admin.POST("/tools", deps.Tools.Create)
				admin.GET("/tools/:id/edit", deps.Tools.Edit)
				admin.POST("/tools/:id", deps.Tools.Update)
				admin.POST("/tools/:id/delete", deps.Tools.Delete)
			}

			// Per-tool access-token management. The plaintext token is returned
			// exactly once by create; no route re-reads it. GETs need a session,
			// POSTs need a CSRF token via the group middleware.
			if deps.Tokens != nil {
				admin.GET("/tools/:id/tokens", deps.Tokens.List)
				admin.GET("/tools/:id/tokens/new", deps.Tokens.New)
				admin.POST("/tools/:id/tokens", deps.Tokens.Create)
				admin.POST("/tools/:id/tokens/:token_id/revoke", deps.Tokens.Revoke)
			}

			// Observability views: read-only audit history and tool health.
			if deps.Activity != nil {
				admin.GET("/activity", deps.Activity.List)
			}
			if deps.Health != nil {
				admin.GET("/health", deps.Health.List)
			}

			// Dynamic tool installer. Uploading a package POSTs to the separate
			// installer service (never to Docker from Core); every mutation goes
			// through the CSRF-protected admin group. Enable/disable/uninstall are
			// HTMX-driven so the row is replaced in place.
			if deps.Installer != nil {
				admin.GET("/installer", deps.Installer.List)
				admin.POST("/installer", deps.Installer.Create)
				admin.POST("/installer/:slug/enable", deps.Installer.Enable)
				admin.POST("/installer/:slug/disable", deps.Installer.Disable)
				admin.DELETE("/installer/:slug", deps.Installer.Delete)
			}
		}
	}

	return r
}

// Ensure the concrete session service satisfies the middleware contract.
var _ middleware.SessionValidator = (*service.SessionService)(nil)
