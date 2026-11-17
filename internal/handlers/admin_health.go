package handlers

import (
	"context"
	"html/template"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/winduputra/MyCorePlat/internal/model"
)

// HealthReader is the subset of the health tool list the admin UI needs.
type HealthReader interface {
	List(ctx context.Context) ([]model.Tool, error)
}

// HealthSnapshotter loads the latest check per tool.
type HealthSnapshotter interface {
	LatestByTool(ctx context.Context, toolIDs []uint64) (map[uint64]*model.ToolHealthCheck, error)
}

// AdminHealthHandler renders per-tool health status.
type AdminHealthHandler struct {
	tools  HealthReader
	health HealthSnapshotter
	tmpl   *template.Template
}

// NewAdminHealthHandler builds the handler and parses its page template.
func NewAdminHealthHandler(tools HealthReader, health HealthSnapshotter) (*AdminHealthHandler, error) {
	set, err := template.New("health_list").
		Funcs(adminTemplateFuncs()).
		ParseFS(templateFS, "templates/layouts/*.tmpl", "templates/pages/health_list.html.tmpl")
	if err != nil {
		return nil, err
	}
	return &AdminHealthHandler{tools: tools, health: health, tmpl: set}, nil
}

type healthRow struct {
	ID         uint64
	Name       string
	Slug       string
	LastStatus string
	CheckedAt  *time.Time
	LatencyMS  *int
	Reason     string
}

type healthListData struct {
	Title     string
	Rows      []healthRow
	Error     string
	CSRFToken string
}

func (d *healthListData) setCSRFToken(token string) { d.CSRFToken = token }

// List renders the health dashboard.
func (h *AdminHealthHandler) List(c *gin.Context) {
	tools, err := h.tools.List(c.Request.Context())
	if err != nil {
		h.render(c, http.StatusInternalServerError, healthListData{Title: "Status Kesehatan Tool", Error: "gagal memuat daftar tool"})
		return
	}
	ids := make([]uint64, 0, len(tools))
	for _, t := range tools {
		ids = append(ids, t.ID)
	}
	latest, _ := h.health.LatestByTool(c.Request.Context(), ids)

	rows := make([]healthRow, 0, len(tools))
	for _, t := range tools {
		row := healthRow{ID: t.ID, Name: t.Name, Slug: t.Slug}
		if check := latest[t.ID]; check != nil {
			row.LastStatus = check.Status
			row.CheckedAt = &check.CheckedAt
			row.LatencyMS = check.LatencyMS
			if check.ErrorMessage != nil {
				row.Reason = *check.ErrorMessage
			}
		}
		rows = append(rows, row)
	}
	h.render(c, http.StatusOK, healthListData{Title: "Status Kesehatan Tool", Rows: rows})
}

func (h *AdminHealthHandler) render(c *gin.Context, status int, data healthListData) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.Status(status)
	if err := h.tmpl.ExecuteTemplate(c.Writer, "health_list", withCSRF(c, data)); err != nil {
		c.String(http.StatusInternalServerError, "render error")
	}
}
