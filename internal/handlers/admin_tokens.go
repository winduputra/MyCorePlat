package handlers

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/winduputra/MyCorePlat/internal/middleware"
	"github.com/winduputra/MyCorePlat/internal/model"
	"github.com/winduputra/MyCorePlat/internal/service"
)

// TokenService is the subset of the access-token service the admin handler needs.
// Declared here so the handler is unit-testable without a database.
type TokenService interface {
	Create(ctx context.Context, in service.AccessTokenInput, now time.Time) (string, *model.AccessToken, error)
	Validate(ctx context.Context, plaintext string, toolID uint64, now time.Time) (*model.AccessToken, error)
	Revoke(ctx context.Context, toolID, id uint64, now time.Time) error
	ListByTool(ctx context.Context, toolID uint64) ([]model.AccessToken, error)
}

// AdminTokensOptions configures the admin token handler.
type AdminTokensOptions struct {
	// DefaultTTLDays is the expiry offered in the create form when the admin does
	// not pick a date. Zero means the service default is used.
	DefaultTTLDays int
}

// AdminTokensHandler serves the per-tool token management pages. Every route is
// registered behind RequireAuth + RequireCSRF by the router. There is NO endpoint
// that returns a plaintext token after creation.
type AdminTokensHandler struct {
	tools    ToolService
	tokens   TokenService
	opts     AdminTokensOptions
	tmpl     map[string]*template.Template
	activity ActivityRecorder
	// ipResolver derives the client address for audit rows. Nil trusts only the
	// TCP peer (default).
	ipResolver *service.ClientIPResolver
}

// SetClientIPResolver configures client-address derivation for audit logging.
func (h *AdminTokensHandler) SetClientIPResolver(resolver *service.ClientIPResolver) {
	h.ipResolver = resolver
}

// SetActivityRecorder attaches the audit recorder. Nil disables auditing.
func (h *AdminTokensHandler) SetActivityRecorder(recorder ActivityRecorder) {
	h.activity = recorder
}

// recordToken writes an audit row for a token mutation. It records only the
// non-secret token prefix and label — never the plaintext or the hash.
func (h *AdminTokensHandler) recordToken(c *gin.Context, action string, toolID, tokenID uint64, metadata map[string]any) {
	if h.activity == nil {
		return
	}
	entry := service.ActivityEntry{
		ActorType:  model.ActorTypeAdmin,
		Action:     action,
		EntityType: service.EntityTypeToken,
		EntityID:   &tokenID,
		ToolID:     &toolID,
		IPAddress:  clientAddr(c, h.ipResolver),
		UserAgent:  c.Request.UserAgent(),
		Metadata:   metadata,
	}
	if adminID, ok := middleware.AdminIDFromContext(c); ok {
		entry.ActorID = &adminID
	}
	h.activity.Record(c.Request.Context(), entry)
}

// NewAdminTokensHandler builds the handler and parses the embedded templates.
//
// Like the tools handler, each page is parsed into its own template set (layout +
// one page) because every page defines a "content" template the layout executes.
func NewAdminTokensHandler(tools ToolService, tokens TokenService, opts AdminTokensOptions) (*AdminTokensHandler, error) {
	pages := map[string]string{
		"token_list":   "templates/pages/tokens_list.html.tmpl",
		"token_create": "templates/pages/token_create.html.tmpl",
	}
	tmpl := make(map[string]*template.Template, len(pages))
	for name, page := range pages {
		t, err := template.New(name).Funcs(adminTemplateFuncs()).ParseFS(templateFS,
			"templates/layouts/*.tmpl",
			page,
		)
		if err != nil {
			return nil, err
		}
		tmpl[name] = t
	}
	return &AdminTokensHandler{tools: tools, tokens: tokens, opts: opts, tmpl: tmpl}, nil
}

// tokenListData is the view model for the per-tool token list.
type tokenListData struct {
	Title     string
	Tool      *model.Tool
	ToolID    uint64
	Tokens    []model.AccessToken
	Created   *createdToken
	Error     string
	AnyLive   bool
	NoticeCSR string
}

// createdToken carries the one-time plaintext shown immediately after creation.
// It is never persisted or re-read.
type createdToken struct {
	Label     string
	Plaintext string
	ExpiresAt time.Time
}

// tokenCreateData is the view model for the create form.
type tokenCreateData struct {
	Title      string
	Tool       *model.Tool
	ToolID     uint64
	FormAction string
	Error      string
}

// List renders the token table for one tool. It never shows a plaintext token.
func (h *AdminTokensHandler) List(c *gin.Context) {
	toolID, ok := parseIDParam(c)
	if !ok {
		c.String(http.StatusNotFound, "tool not found")
		return
	}
	tool, err := h.tools.Get(c.Request.Context(), toolID)
	if err != nil {
		h.respondToolError(c, err)
		return
	}
	tokens, err := h.tokens.ListByTool(c.Request.Context(), toolID)
	if err != nil {
		h.render(c, http.StatusInternalServerError, "token_list", tokenListData{
			Title:  "Token Akses",
			Tool:   tool,
			ToolID: toolID,
			Error:  "gagal memuat daftar token",
		})
		return
	}
	anyLive := false
	for _, tok := range tokens {
		if tok.IsLive(time.Now()) {
			anyLive = true
			break
		}
	}
	h.render(c, http.StatusOK, "token_list", tokenListData{
		Title:   "Token Akses — " + tool.Name,
		Tool:    tool,
		ToolID:  toolID,
		Tokens:  tokens,
		AnyLive: anyLive,
	})
}

// New shows the create-token form for a tool.
func (h *AdminTokensHandler) New(c *gin.Context) {
	toolID, ok := parseIDParam(c)
	if !ok {
		c.String(http.StatusNotFound, "tool not found")
		return
	}
	tool, err := h.tools.Get(c.Request.Context(), toolID)
	if err != nil {
		h.respondToolError(c, err)
		return
	}
	h.render(c, http.StatusOK, "token_create", tokenCreateData{
		Title:      "Buat Token — " + tool.Name,
		Tool:       tool,
		ToolID:     toolID,
		FormAction: "/admin/tools/" + strconv.FormatUint(toolID, 10) + "/tokens",
	})
}

// Create mints a token and renders the plaintext EXACTLY ONCE. Subsequent views
// show only the prefix. The admin who created it is taken from the session
// context, never from the form.
func (h *AdminTokensHandler) Create(c *gin.Context) {
	toolID, ok := parseIDParam(c)
	if !ok {
		c.String(http.StatusNotFound, "tool not found")
		return
	}
	adminID, ok := middleware.AdminIDFromContext(c)
	if !ok || adminID == 0 {
		// The router guarantees an authenticated admin; defensive fallback.
		c.String(http.StatusUnauthorized, "authentication required")
		return
	}
	tool, err := h.tools.Get(c.Request.Context(), toolID)
	if err != nil {
		h.respondToolError(c, err)
		return
	}

	expiresAt, err := parseExpiry(c.PostForm("expires_at"))
	if err != nil {
		h.render(c, http.StatusBadRequest, "token_create", tokenCreateData{
			Title:      "Buat Token — " + tool.Name,
			Tool:       tool,
			ToolID:     toolID,
			FormAction: "/admin/tools/" + strconv.FormatUint(toolID, 10) + "/tokens",
			Error:      "tanggal kedaluwarsa tidak valid",
		})
		return
	}

	in := service.AccessTokenInput{
		ToolID:           toolID,
		CreatedByAdminID: adminID,
		RecipientLabel:   c.PostForm("recipient_label"),
		ExpiresAt:        expiresAt,
	}
	plaintext, token, err := h.tokens.Create(c.Request.Context(), in, time.Now())
	if err != nil {
		h.render(c, http.StatusBadRequest, "token_create", tokenCreateData{
			Title:      "Buat Token — " + tool.Name,
			Tool:       tool,
			ToolID:     toolID,
			FormAction: "/admin/tools/" + strconv.FormatUint(toolID, 10) + "/tokens",
			Error:      tokenError(err),
		})
		return
	}

	// Re-list so the new token appears, and surface the plaintext one single time.
	tokens, _ := h.tokens.ListByTool(c.Request.Context(), toolID)
	label := ""
	if token.RecipientLabel != nil {
		label = *token.RecipientLabel
	}
	h.recordToken(c, service.ActionTokenCreated, toolID, token.ID, map[string]any{
		"slug":       tool.Slug,
		"prefix":     token.TokenPrefix,
		"label":      label,
		"expires_at": token.ExpiresAt.UTC().Format(time.RFC3339),
	})
	h.render(c, http.StatusOK, "token_list", tokenListData{
		Title:  "Token Akses — " + tool.Name,
		Tool:   tool,
		ToolID: toolID,
		Tokens: tokens,
		Created: &createdToken{
			Label:     label,
			Plaintext: plaintext,
			ExpiresAt: token.ExpiresAt,
		},
		AnyLive: true,
	})
}

// Revoke marks a token revoked. Cross-tool and unknown tokens both report 404 so
// no information about other tools leaks.
func (h *AdminTokensHandler) Revoke(c *gin.Context) {
	toolID, ok := parseIDParam(c)
	if !ok {
		c.String(http.StatusNotFound, "tool not found")
		return
	}
	tokenID := parseSubIDParam(c, "token_id")
	if tokenID == 0 {
		c.String(http.StatusNotFound, "token not found")
		return
	}
	if err := h.tokens.Revoke(c.Request.Context(), toolID, tokenID, time.Now()); err != nil {
		if errors.Is(err, service.ErrAccessTokenNotFound) {
			c.String(http.StatusNotFound, "token not found")
			return
		}
		c.String(http.StatusInternalServerError, "gagal mencabut token")
		return
	}
	h.recordToken(c, service.ActionTokenRevoked, toolID, tokenID, map[string]any{})
	if c.GetHeader("HX-Request") != "" {
		c.String(http.StatusOK, "")
		return
	}
	c.Redirect(http.StatusSeeOther, "/admin/tools/"+strconv.FormatUint(toolID, 10)+"/tokens")
}

// respondToolError maps a tool lookup error to a response.
func (h *AdminTokensHandler) respondToolError(c *gin.Context, err error) {
	if errors.Is(err, service.ErrToolNotFound) {
		c.String(http.StatusNotFound, "tool not found")
		return
	}
	c.String(http.StatusInternalServerError, "gagal memuat tool")
}

// render writes a named template with the shared HTML headers.
func (h *AdminTokensHandler) render(c *gin.Context, status int, name string, data any) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.Status(status)
	set, ok := h.tmpl[name]
	if !ok {
		c.String(http.StatusInternalServerError, "render error")
		return
	}
	if err := set.ExecuteTemplate(c.Writer, name, data); err != nil {
		c.String(status, "render error")
	}
}

// parseExpiry parses an optional datetime-local value ("2006-01-02T15:04"). An
// empty value returns the zero time, letting the service apply its default TTL.
func parseExpiry(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}
	// Accept both the datetime-local form and a plain date.
	for _, layout := range []string{"2006-01-02T15:04", "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, raw, time.UTC); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, errors.New("invalid expiry")
}

// parseSubIDParam parses an extra numeric route parameter by name.
func parseSubIDParam(c *gin.Context, name string) uint64 {
	id, err := strconv.ParseUint(c.Param(name), 10, 64)
	if err != nil {
		return 0
	}
	return id
}

// tokenError maps a token service error to a user-facing message.
func tokenError(err error) string {
	switch {
	case errors.Is(err, service.ErrAccessTokenExpiryRequired):
		return "tanggal kedaluwarsa wajib diisi dan harus di masa depan"
	case errors.Is(err, service.ErrAccessTokenExpiryTooLong):
		return "tanggal kedaluwarsa melebihi batas maksimum"
	default:
		return "data token tidak valid"
	}
}

// adminTemplateFuncs returns the shared template helpers for admin pages.
func adminTemplateFuncs() template.FuncMap {
	return template.FuncMap{
		"deref": func(p *string) string {
			if p == nil {
				return ""
			}
			return *p
		},
		"timefmt": func(t time.Time) string {
			if t.IsZero() {
				return "-"
			}
			return t.UTC().Format("2006-01-02 15:04")
		},
		"timefmtPtr": func(t *time.Time) string {
			if t == nil {
				return "-"
			}
			return t.UTC().Format("2006-01-02 15:04")
		},
	}
}
