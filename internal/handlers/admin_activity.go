package handlers

import (
	"context"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/winduputra/MyCorePlat/internal/model"
	"github.com/winduputra/MyCorePlat/internal/service"
)

// ActivityLister is the subset of the activity service the admin UI needs.
type ActivityLister interface {
	List(ctx context.Context, filter service.ActivityFilter) ([]model.ActivityLog, int64, error)
}

// AdminActivityHandler serves the paginated activity-log history.
type AdminActivityHandler struct {
	activity ActivityLister
	pageSize int
	tmpl     *template.Template
}

// NewAdminActivityHandler builds the handler and parses its page template.
func NewAdminActivityHandler(activity ActivityLister) (*AdminActivityHandler, error) {
	set, err := template.New("activity_list").
		Funcs(adminTemplateFuncs()).
		ParseFS(templateFS, "templates/layouts/*.tmpl", "templates/pages/activity_list.html.tmpl")
	if err != nil {
		return nil, err
	}
	return &AdminActivityHandler{activity: activity, pageSize: service.DefaultActivityPageSize, tmpl: set}, nil
}

// activityFilterView carries the raw filter values back into the form.
type activityFilterView struct {
	Action, EntityType string
	ToolIDValue        string
	FromValue, ToValue string
}

type activityListData struct {
	Title      string
	Entries    []model.ActivityLog
	Filter     activityFilterView
	Error      string
	Total      int64
	Page       int
	TotalPages int
	HasPrev    bool
	HasNext    bool
	PrevURL    string
	NextURL    string
	CSRFToken  string
}

func (d *activityListData) setCSRFToken(token string) { d.CSRFToken = token }

// List renders a filtered, paginated view of the audit trail.
func (h *AdminActivityHandler) List(c *gin.Context) {
	filter, view := parseActivityFilter(c)
	page := parsePage(c.Query("page"))
	filter.Limit = h.pageSize
	filter.Offset = (page - 1) * h.pageSize

	entries, total, err := h.activity.List(c.Request.Context(), filter)
	if err != nil {
		h.render(c, http.StatusInternalServerError, activityListData{
			Title: "Riwayat Aktivitas",
			Error: "gagal memuat riwayat aktivitas",
		})
		return
	}

	totalPages := 1
	if total > 0 {
		totalPages = int((total + int64(h.pageSize) - 1) / int64(h.pageSize))
	}
	data := activityListData{
		Title:      "Riwayat Aktivitas",
		Entries:    entries,
		Filter:     view,
		Total:      total,
		Page:       page,
		TotalPages: totalPages,
		HasPrev:    page > 1,
		HasNext:    int64(page)*int64(h.pageSize) < total,
		PrevURL:    activityPageURL(c, page-1),
		NextURL:    activityPageURL(c, page+1),
	}
	h.render(c, http.StatusOK, data)
}

// parseActivityFilter reads and validates the query filters.
func parseActivityFilter(c *gin.Context) (service.ActivityFilter, activityFilterView) {
	filter := service.ActivityFilter{Action: c.Query("action"), EntityType: c.Query("entity_type")}
	view := activityFilterView{Action: filter.Action, EntityType: filter.EntityType, ToolIDValue: c.Query("tool_id")}
	if id, err := strconv.ParseUint(c.Query("tool_id"), 10, 64); err == nil && id > 0 {
		filter.ToolID = &id
	}
	if t, ok := parseDateQuery(c.Query("from")); ok {
		filter.From = &t
		view.FromValue = c.Query("from")
	}
	if t, ok := parseDateQuery(c.Query("to")); ok {
		// Inclusive end-of-day.
		end := t.Add(24*time.Hour - time.Nanosecond)
		filter.To = &end
		view.ToValue = c.Query("to")
	}
	return filter, view
}

// parseDateQuery parses a YYYY-MM-DD date as UTC midnight.
func parseDateQuery(raw string) (time.Time, bool) {
	if raw == "" {
		return time.Time{}, false
	}
	t, err := time.ParseInLocation("2006-01-02", raw, time.UTC)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// parsePage clamps a 1-based page number.
func parsePage(raw string) int {
	page, err := strconv.Atoi(raw)
	if err != nil || page < 1 {
		return 1
	}
	return page
}

// activityPageURL builds a page link preserving the active filters.
func activityPageURL(c *gin.Context, page int) string {
	if page < 1 {
		page = 1
	}
	q := url.Values{}
	for _, key := range []string{"action", "entity_type", "tool_id", "from", "to"} {
		if v := c.Query(key); v != "" {
			q.Set(key, v)
		}
	}
	q.Set("page", strconv.Itoa(page))
	return "/admin/activity?" + q.Encode()
}

func (h *AdminActivityHandler) render(c *gin.Context, status int, data activityListData) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.Status(status)
	if err := h.tmpl.ExecuteTemplate(c.Writer, "activity_list", withCSRF(c, data)); err != nil {
		// Never surface template errors to the client.
		c.String(http.StatusInternalServerError, "render error")
	}
}
