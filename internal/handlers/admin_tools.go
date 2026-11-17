package handlers

import (
	"context"
	"embed"
	"errors"
	"html/template"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/winduputra/MyCorePlat/internal/middleware"
	"github.com/winduputra/MyCorePlat/internal/model"
	"github.com/winduputra/MyCorePlat/internal/service"
)

//go:embed all:templates
var templateFS embed.FS

// ToolService is the subset of the tool service the admin handler needs.
// Declaring it here keeps the handler thin and unit-testable without a database.
type ToolService interface {
	List(ctx context.Context) ([]model.Tool, error)
	Get(ctx context.Context, id uint64) (*model.Tool, error)
	Create(ctx context.Context, in service.ToolInput) (*model.Tool, error)
	Update(ctx context.Context, id uint64, in service.ToolInput) (*model.Tool, error)
	Delete(ctx context.Context, id uint64) error
}

// AdminToolsOptions configures the admin tool handler.
type AdminToolsOptions struct {
	// TemplatesDir is retained for compatibility; templates are embedded.
	TemplatesDir string
}

// AdminToolsHandler serves the admin tool registry CRUD pages. Every route is
// registered behind RequireAuth + RequireCSRF (mutations) by the router.
type AdminToolsHandler struct {
	tools    ToolService
	tmpl     map[string]*template.Template
	activity ActivityRecorder
	// ipResolver derives the client address for audit rows. Nil trusts only the
	// TCP peer (default).
	ipResolver *service.ClientIPResolver
}

// SetClientIPResolver configures client-address derivation for audit logging.
func (h *AdminToolsHandler) SetClientIPResolver(resolver *service.ClientIPResolver) {
	h.ipResolver = resolver
}

// SetActivityRecorder attaches the audit recorder. Nil disables auditing.
func (h *AdminToolsHandler) SetActivityRecorder(recorder ActivityRecorder) {
	h.activity = recorder
}

// recordTool writes an audit row for a tool mutation. Only non-sensitive
// descriptors are recorded (slug, name, status, access type) — never secrets.
func (h *AdminToolsHandler) recordTool(c *gin.Context, action string, tool *model.Tool) {
	if h.activity == nil || tool == nil {
		return
	}
	entry := service.ActivityEntry{
		ActorType:  model.ActorTypeAdmin,
		Action:     action,
		EntityType: service.EntityTypeTool,
		EntityID:   &tool.ID,
		ToolID:     &tool.ID,
		IPAddress:  clientAddr(c, h.ipResolver),
		UserAgent:  c.Request.UserAgent(),
		Metadata: map[string]any{
			"slug":        tool.Slug,
			"name":        tool.Name,
			"status":      tool.Status,
			"access_type": tool.AccessType,
		},
	}
	if adminID, ok := middleware.AdminIDFromContext(c); ok {
		entry.ActorID = &adminID
	}
	h.activity.Record(c.Request.Context(), entry)
}

// NewAdminToolsHandler builds the handler and parses the embedded templates.
//
// Each page is parsed into its OWN template set (layout + one page file) because
// every page defines a template named "content" that the shared layout executes.
// Parsing all pages into a single set would make the last definition of
// "content" win globally and every page would render the same body.
func NewAdminToolsHandler(tools ToolService, _ AdminToolsOptions) (*AdminToolsHandler, error) {
	funcs := adminTemplateFuncs()
	pages := map[string]string{
		"tool_list": "templates/pages/tools_list.html.tmpl",
		"tool_form": "templates/pages/tool_form.html.tmpl",
	}
	tmpl := make(map[string]*template.Template, len(pages))
	for name, page := range pages {
		t, err := template.New(name).Funcs(funcs).ParseFS(templateFS,
			"templates/layouts/*.tmpl",
			page,
		)
		if err != nil {
			return nil, err
		}
		tmpl[name] = t
	}
	return &AdminToolsHandler{tools: tools, tmpl: tmpl}, nil
}

// toolListData is the view model for the list page.
type toolListData struct {
	Title string
	Tools []model.Tool
	Error string
}

// toolFormData is the view model for the create/edit form.
type toolFormData struct {
	Title      string
	Tool       model.Tool
	FormAction string
	Error      string
}

// List renders the tool registry table.
func (h *AdminToolsHandler) List(c *gin.Context) {
	tools, err := h.tools.List(c.Request.Context())
	if err != nil {
		h.render(c, http.StatusInternalServerError, "tool_list", toolListData{
			Title: "Daftar Tool",
			Error: "gagal memuat daftar tool",
		})
		return
	}
	h.render(c, http.StatusOK, "tool_list", toolListData{
		Title: "Daftar Tool",
		Tools: tools,
	})
}

// New shows the empty create form.
func (h *AdminToolsHandler) New(c *gin.Context) {
	h.render(c, http.StatusOK, "tool_form", toolFormData{
		Title:      "Tambah Tool",
		FormAction: "/admin/tools",
		Tool: model.Tool{
			AccessType:      model.ToolAccessPublic,
			HealthcheckPath: "/health",
			Status:          model.ToolStatusDraft,
		},
	})
}

// Create handles form submission for a new tool.
func (h *AdminToolsHandler) Create(c *gin.Context) {
	in := parseToolInput(c)
	tool, err := h.tools.Create(c.Request.Context(), in)
	if err != nil {
		status := http.StatusBadRequest
		h.render(c, status, "tool_form", toolFormData{
			Title:      "Tambah Tool",
			FormAction: "/admin/tools",
			Tool:       inputToView(in),
			Error:      toolError(err),
		})
		return
	}
	h.recordTool(c, service.ActionToolCreated, tool)
	c.Redirect(http.StatusSeeOther, "/admin/tools/"+strconv.FormatUint(tool.ID, 10)+"/edit")
}

// Edit shows the populated edit form.
func (h *AdminToolsHandler) Edit(c *gin.Context) {
	id, ok := parseIDParam(c)
	if !ok {
		c.String(http.StatusNotFound, "tool not found")
		return
	}
	tool, err := h.tools.Get(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, service.ErrToolNotFound) {
			c.String(http.StatusNotFound, "tool not found")
			return
		}
		c.String(http.StatusInternalServerError, "gagal memuat tool")
		return
	}
	h.render(c, http.StatusOK, "tool_form", toolFormData{
		Title:      "Edit Tool",
		Tool:       *tool,
		FormAction: "/admin/tools/" + strconv.FormatUint(id, 10),
	})
}

// Update handles form submission for an existing tool.
func (h *AdminToolsHandler) Update(c *gin.Context) {
	id, ok := parseIDParam(c)
	if !ok {
		c.String(http.StatusNotFound, "tool not found")
		return
	}
	in := parseToolInput(c)
	tool, err := h.tools.Update(c.Request.Context(), id, in)
	if err != nil {
		if errors.Is(err, service.ErrToolNotFound) {
			c.String(http.StatusNotFound, "tool not found")
			return
		}
		h.render(c, http.StatusBadRequest, "tool_form", toolFormData{
			Title:      "Edit Tool",
			FormAction: "/admin/tools/" + strconv.FormatUint(id, 10),
			Tool:       inputToView(in),
			Error:      toolError(err),
		})
		return
	}
	h.recordTool(c, service.ActionToolUpdated, tool)
	c.Redirect(http.StatusSeeOther, "/admin/tools/"+strconv.FormatUint(tool.ID, 10)+"/edit")
}

// Delete soft-deletes a tool. It answers both HTMX (empty row) and plain POST
// (redirect) callers.
func (h *AdminToolsHandler) Delete(c *gin.Context) {
	id, ok := parseIDParam(c)
	if !ok {
		c.String(http.StatusNotFound, "tool not found")
		return
	}
	if err := h.tools.Delete(c.Request.Context(), id); err != nil {
		if errors.Is(err, service.ErrToolNotFound) {
			c.String(http.StatusNotFound, "tool not found")
			return
		}
		c.String(http.StatusInternalServerError, "gagal menghapus tool")
		return
	}
	h.recordTool(c, service.ActionToolDeleted, &model.Tool{ID: id})
	if c.GetHeader("HX-Request") != "" {
		// Empty body removes the row via hx-swap="outerHTML".
		c.String(http.StatusOK, "")
		return
	}
	c.Redirect(http.StatusSeeOther, "/admin/tools")
}

// render writes a named template with the shared HTML headers.
func (h *AdminToolsHandler) render(c *gin.Context, status int, name string, data any) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.Status(status)
	set, ok := h.tmpl[name]
	if !ok {
		c.String(http.StatusInternalServerError, "render error")
		return
	}
	if err := set.ExecuteTemplate(c.Writer, name, data); err != nil {
		// Headers are already written; log-free fail-safe response.
		c.String(status, "render error")
	}
}

// parseToolInput reads and trims the tool form fields. It performs no
// authorization decisions â€” the service validates.
func parseToolInput(c *gin.Context) service.ToolInput {
	order, _ := strconv.Atoi(c.PostForm("display_order"))
	return service.ToolInput{
		Slug:               c.PostForm("slug"),
		Name:               c.PostForm("name"),
		Description:        c.PostForm("description"),
		Category:           c.PostForm("category"),
		Version:            c.PostForm("version"),
		Runtime:            c.PostForm("runtime"),
		AccessType:         c.PostForm("access_type"),
		UpstreamURL:        c.PostForm("upstream_url"),
		HealthcheckPath:    c.PostForm("healthcheck_path"),
		Status:             c.PostForm("status"),
		MaintenanceMessage: c.PostForm("maintenance_message"),
		DisplayOrder:       order,
	}
}

// parseIDParam parses the ":id" route parameter.
func parseIDParam(c *gin.Context) (uint64, bool) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || id == 0 {
		return 0, false
	}
	return id, true
}

// toolError maps a service error to a user-facing message.
func toolError(err error) string {
	switch {
	case errors.Is(err, service.ErrDuplicateSlug):
		return "slug sudah digunakan"
	case errors.Is(err, service.ErrInvalidUpstream):
		return "URL upstream tidak valid atau tidak diizinkan"
	default:
		return "data tool tidak valid"
	}
}

// inputToView re-renders the submitted input as a model for the form on error.
func inputToView(in service.ToolInput) model.Tool {
	return model.Tool{
		Slug:               in.Slug,
		Name:               in.Name,
		Description:        nilIfEmpty(in.Description),
		Category:           nilIfEmpty(in.Category),
		Version:            nilIfEmpty(in.Version),
		Runtime:            nilIfEmpty(in.Runtime),
		AccessType:         in.AccessType,
		UpstreamURL:        in.UpstreamURL,
		HealthcheckPath:    in.HealthcheckPath,
		Status:             in.Status,
		MaintenanceMessage: nilIfEmpty(in.MaintenanceMessage),
		DisplayOrder:       in.DisplayOrder,
	}
}

// nilIfEmpty returns a pointer to s, or nil when s is empty.
func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
