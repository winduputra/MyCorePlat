package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// RootHandler serves the site root ("/"). It decides where a visitor should go
// based on whether they already hold a valid admin session:
//
//   - authenticated  -> redirect to the admin dashboard (/admin/tools)
//   - anonymous      -> redirect to the login page (/admin/login)
//
// Both destinations are reachable without this redirect, but sending the bare
// domain to the right place keeps https://<host>/ from returning 404 and gives
// browsers a usable entry point.
type RootHandler struct {
	// isAuthenticated reports whether the request carries a valid session. A
	// nil func means "treat every visitor as anonymous", which safely routes to
	// the login page.
	isAuthenticated func(c *gin.Context) bool
}

// NewRootHandler builds the root handler. isAuthenticated may be nil (tests
// that only check the redirect target for anonymous visitors).
func NewRootHandler(isAuthenticated func(c *gin.Context) bool) *RootHandler {
	return &RootHandler{isAuthenticated: isAuthenticated}
}

// catalogRootHandler serves the public tool catalog to anonymous visitors and
// still sends an authenticated admin to the dashboard.
//
// Rationale: the bare domain should show something useful to the public. An
// admin who is already logged in almost certainly wants the dashboard, so they
// are redirected as before. Both branches read only the session cookie.
type catalogRootHandler struct {
	isAuthenticated func(c *gin.Context) bool
	catalog         *CatalogHandler
}

// NewRootHandlerForCatalog builds a root handler that renders the public
// catalog for anonymous visitors. A nil isAuthenticated treats every visitor
// as anonymous (useful in tests).
func NewRootHandlerForCatalog(isAuthenticated func(c *gin.Context) bool, catalog *CatalogHandler) gin.HandlerFunc {
	h := &catalogRootHandler{isAuthenticated: isAuthenticated, catalog: catalog}
	return h.Serve
}

// Serve redirects authenticated admins to the dashboard and renders the
// catalog for everyone else.
func (h *catalogRootHandler) Serve(c *gin.Context) {
	if h.isAuthenticated != nil && h.isAuthenticated(c) {
		c.Redirect(http.StatusFound, "/admin/tools")
		return
	}
	h.catalog.Serve(c)
}

// Serve decides the redirect target and issues a 302.
func (h *RootHandler) Serve(c *gin.Context) {
	target := "/admin/login"
	if h.isAuthenticated != nil && h.isAuthenticated(c) {
		target = "/admin/tools"
	}
	c.Redirect(http.StatusFound, target)
}
