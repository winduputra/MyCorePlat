package handlers

import (
	"context"
	"errors"
	"html"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/winduputra/MyCorePlat/internal/model"
	"github.com/winduputra/MyCorePlat/internal/service"
)

// preAuthCSRFCookieName must match middleware.PreAuthCSRFCookieName. It is
// duplicated here to keep handlers free of a middleware import cycle; a test
// asserts the two stay in sync.
const preAuthCSRFCookieName = "bpbj_login_csrf"

// AuthService is the subset of the auth service the handler needs. Declaring it
// here keeps the handler thin and unit-testable without a database.
type AuthService interface {
	Login(ctx context.Context, username, password string, meta service.SessionMeta) (string, *model.AdminSession, error)
	Logout(ctx context.Context, sessionID uint64) error
}

// PreAuthCSRFIssuer issues signed pre-authentication CSRF tokens.
type PreAuthCSRFIssuer interface {
	Issue() (token string, expiry time.Time, err error)
}

// AuthOptions configures cookie behavior for the auth handlers.
type AuthOptions struct {
	CookieName   string
	CookieSecure bool
	CookiePath   string
	SessionTTL   int // seconds
	// PreAuthCSRFTTL bounds the lifetime of the pre-login CSRF cookie in
	// seconds. Values <= 0 fall back to 600 seconds (10 minutes).
	PreAuthCSRFTTL int
	// LoginRateWindow is the window used by the login limiter, used only to
	// derive the Retry-After header. Values <= 0 fall back to 60 seconds.
	LoginRateWindow time.Duration
}

// AuthHandler serves the admin login/logout endpoints.
type AuthHandler struct {
	auth        AuthService
	preAuthCSRF PreAuthCSRFIssuer
	opts        AuthOptions
	activity    ActivityRecorder
	// ipLimiter and userLimiter throttle failed login attempts per connecting
	// IP and per submitted username respectively. Either may be nil, which
	// disables that dimension (used by unit tests). They must retain state
	// across requests, so they are shared, not per-request.
	ipLimiter   *service.RateLimiter
	userLimiter *service.RateLimiter
	// ipResolver derives the client address. Nil keeps the safe default of
	// trusting only the TCP peer (no forwarding headers).
	ipResolver *service.ClientIPResolver
}

// SetClientIPResolver configures how the handler derives the client address for
// rate limiting and audit logging. A nil resolver (the default) trusts only the
// TCP peer address, ignoring any forwarded header. Call before serving requests.
func (h *AuthHandler) SetClientIPResolver(resolver *service.ClientIPResolver) {
	h.ipResolver = resolver
}

// ActivityRecorder is the narrow audit interface handlers need. A nil recorder
// disables auditing (used by unit tests that do not exercise logging).
type ActivityRecorder interface {
	Record(ctx context.Context, entry service.ActivityEntry) bool
}

// SetActivityRecorder attaches the audit recorder. Call before serving requests.
func (h *AuthHandler) SetActivityRecorder(recorder ActivityRecorder) {
	h.activity = recorder
}

// SetLoginLimiters attaches the per-IP and per-username login throttles. Call
// before serving requests. Passing nil for a limiter disables that dimension.
func (h *AuthHandler) SetLoginLimiters(ipLimiter, userLimiter *service.RateLimiter) {
	h.ipLimiter = ipLimiter
	h.userLimiter = userLimiter
}

// NewAuthHandler builds an AuthHandler. preAuthCSRF may be nil, in which case
// the login form omits the pre-auth token (only acceptable in tests).
func NewAuthHandler(auth AuthService, preAuthCSRF PreAuthCSRFIssuer, opts AuthOptions) *AuthHandler {
	if opts.CookieName == "" {
		opts.CookieName = "bpbj_admin_session"
	}
	if opts.CookiePath == "" {
		opts.CookiePath = "/"
	}
	if opts.PreAuthCSRFTTL <= 0 {
		opts.PreAuthCSRFTTL = 600
	}
	return &AuthHandler{auth: auth, preAuthCSRF: preAuthCSRF, opts: opts}
}

// LoginPage renders the login form (GET) and issues the pre-auth CSRF cookie
// plus the matching hidden form field.
func (h *AuthHandler) LoginPage(c *gin.Context) {
	token := ""
	if h.preAuthCSRF != nil {
		issued, _, err := h.preAuthCSRF.Issue()
		if err != nil {
			c.String(http.StatusInternalServerError, "login unavailable")
			return
		}
		token = issued
		h.setPreAuthCSRFCookie(c, issued)
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.String(http.StatusOK, renderLoginPage(token))
}

// LoginSubmit handles credential submission (POST). It sets a hardened session
// cookie on success and returns a generic error on failure.
func (h *AuthHandler) LoginSubmit(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")
	if username == "" || password == "" {
		c.String(http.StatusBadRequest, "username and password are required")
		return
	}

	// Throttle by connecting IP and by submitted username before touching the
	// auth service. The IP key uses the resolved client address: the TCP peer by
	// default, or the forwarded address only when the connection comes from a
	// configured trusted proxy. The username key uses the submitted value,
	// normalized to lower case so case variants cannot open fresh buckets.
	clientAddress := clientAddr(c, h.ipResolver)
	ipKey := "login:ip:" + clientAddress
	userKey := "login:user:" + strings.ToLower(strings.TrimSpace(username))
	if (h.ipLimiter != nil && !h.ipLimiter.Allow(ipKey)) ||
		(h.userLimiter != nil && !h.userLimiter.Allow(userKey)) {
		// Generic body: the same message regardless of username existence.
		c.Header("Retry-After", strconv.Itoa(h.retryAfterSeconds()))
		c.String(http.StatusTooManyRequests, "too many login attempts; try again later")
		return
	}

	meta := service.SessionMeta{IPAddress: clientAddr(c, h.ipResolver), UserAgent: c.Request.UserAgent()}
	plaintext, session, err := h.auth.Login(c.Request.Context(), username, password, meta)
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			// Audit the attempt, but never the attempted username: logging it
			// would build a list of valid/invalid account names.
			h.recordAuth(c, nil, service.ActionAdminLoginFailed)
			// Generic message: never reveal whether the username exists.
			c.String(http.StatusUnauthorized, "invalid credentials")
			return
		}
		c.String(http.StatusInternalServerError, "login failed")
		return
	}

	// A successful login is not consumed as a failed attempt: clear the
	// per-username bucket so a legitimate operator is not penalized by earlier
	// typos. The IP bucket is left intact so spraying from one IP stays limited.
	if h.userLimiter != nil {
		h.userLimiter.Reset(userKey)
	}

	h.recordAuth(c, session, service.ActionAdminLogin)
	h.setSessionCookie(c, plaintext, h.opts.SessionTTL, false)
	// The pre-auth CSRF token is single-use: drop it once a real session exists.
	h.setPreAuthCSRFCookie(c, "")
	c.Redirect(http.StatusSeeOther, "/admin/tools")
}

// retryAfterSeconds returns a conservative positive integer number of seconds
// for the Retry-After header, derived from the configured window.
func (h *AuthHandler) retryAfterSeconds() int {
	window := h.opts.LoginRateWindow
	if window <= 0 {
		window = 60 * time.Second
	}
	secs := int(window.Seconds())
	if secs < 1 {
		secs = 1
	}
	return secs
}

// clientIPString extracts the peer IP from RemoteAddr only. It deliberately
// does not read X-Forwarded-For or any other client-supplied header, so an
// attacker cannot escape throttling by rotating forwarded-for values.
// (Superseded by clientAddr + service.ClientIPResolver for configured trusted
// proxies; kept for the peer-only fallback used in tests.)
func clientIPString(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	if host == "" {
		return r.RemoteAddr
	}
	return host
}

// recordAuth writes a login/logout audit row for the acting admin.
func (h *AuthHandler) recordAuth(c *gin.Context, session *model.AdminSession, action string) {
	if h.activity == nil {
		return
	}
	entry := service.ActivityEntry{
		ActorType: model.ActorTypeAdmin,
		Action:    action,
		IPAddress: clientAddr(c, h.ipResolver),
		UserAgent: c.Request.UserAgent(),
	}
	if session != nil {
		adminID := session.AdminID
		entry.ActorID = &adminID
		entry.EntityType = service.EntityTypeAdmin
		entry.EntityID = &adminID
	}
	h.activity.Record(c.Request.Context(), entry)
}

// Logout revokes the current session and clears the cookie (POST).
func (h *AuthHandler) Logout(c *gin.Context) {
	if session, ok := c.Get("auth_session"); ok {
		if s, ok := session.(*model.AdminSession); ok && s != nil {
			h.recordAuth(c, s, service.ActionAdminLogout)
			_ = h.auth.Logout(c.Request.Context(), s.ID)
		}
	}
	h.setSessionCookie(c, "", -1, true)
	c.Redirect(http.StatusSeeOther, "/admin/login")
}

// setSessionCookie writes the session cookie with hardened attributes.
func (h *AuthHandler) setSessionCookie(c *gin.Context, value string, maxAge int, clearing bool) {
	sameSite := http.SameSiteLaxMode
	if clearing {
		maxAge = -1
	}
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     h.opts.CookieName,
		Value:    value,
		Path:     h.opts.CookiePath,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   h.opts.CookieSecure,
		SameSite: sameSite,
	})
}

// setPreAuthCSRFCookie stores the signed pre-auth CSRF token in a hardened
// cookie scoped to /admin. An empty value clears it.
func (h *AuthHandler) setPreAuthCSRFCookie(c *gin.Context, value string) {
	cookie := &http.Cookie{
		Name:     preAuthCSRFCookieName,
		Value:    value,
		Path:     "/admin",
		HttpOnly: true,
		Secure:   h.opts.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	}
	if value == "" {
		cookie.MaxAge = -1
	} else {
		cookie.MaxAge = h.opts.PreAuthCSRFTTL
	}
	http.SetCookie(c.Writer, cookie)
}

// renderLoginPage injects the pre-auth CSRF token into the hidden form field.
func renderLoginPage(token string) string {
	if token == "" {
		return loginPageHTMLWithoutToken
	}
	return insertLoginCSRFToken(loginPageHTMLWithoutToken, token)
}

// loginPageHTML is kept as an alias for compatibility with existing tests.
const loginPageHTML = loginPageHTMLWithoutToken

const loginPageHTMLWithoutToken = `<!DOCTYPE html>
<html lang="id">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Admin Login - Tools BPBJ</title></head>
<body>
<main>
<h1>Admin Login</h1>
<form method="post" action="/admin/login">
<input type="hidden" name="csrf_token" value="{{CSRF_TOKEN}}">
<label for="username">Username</label>
<input id="username" name="username" type="text" autocomplete="username" required>
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password" required>
<button type="submit">Masuk</button>
</form>
</main>
</body>
</html>`

// insertLoginCSRFToken replaces the placeholder with an HTML-escaped token.
func insertLoginCSRFToken(page, token string) string {
	escaped := html.EscapeString(token)
	return strings.Replace(page, "{{CSRF_TOKEN}}", escaped, 1)
}
