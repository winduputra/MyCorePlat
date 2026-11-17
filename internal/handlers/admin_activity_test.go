package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/winduputra/MyCorePlat/internal/model"
	"github.com/winduputra/MyCorePlat/internal/service"
)

// recordingActivityLister captures the last filter and returns canned rows.
type recordingActivityLister struct {
	rows      []model.ActivityLog
	total     int64
	lastFil   service.ActivityFilter
	calls     int
	failError bool
}

func (r *recordingActivityLister) List(_ context.Context, filter service.ActivityFilter) ([]model.ActivityLog, int64, error) {
	r.calls++
	r.lastFil = filter
	if r.failError {
		return nil, 0, context.Canceled
	}
	return r.rows, r.total, nil
}

func newActivityHandlerForTest(t *testing.T, lister ActivityLister) *AdminActivityHandler {
	t.Helper()
	h, err := NewAdminActivityHandler(lister)
	if err != nil {
		t.Fatalf("NewAdminActivityHandler: %v", err)
	}
	return h
}

func activityTestRouter(h *AdminActivityHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/admin/activity", h.List)
	return r
}

func strPtrSim(v string) *string { return &v }

func TestActivityListRenders(t *testing.T) {
	lister := &recordingActivityLister{
		rows: []model.ActivityLog{
			{ID: 1, ActorType: "admin", Action: "tool.create", CreatedAt: time.Now()},
		},
		total: 1,
	}
	r := activityTestRouter(newActivityHandlerForTest(t, lister))

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/activity", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "tool.create") {
		t.Fatalf("body missing action: %s", body)
	}
	if !strings.Contains(body, "Total: 1") {
		t.Fatalf("body missing total: %s", body)
	}
}

func TestActivityListAppliesPagingAndDefaults(t *testing.T) {
	lister := &recordingActivityLister{total: 0}
	r := activityTestRouter(newActivityHandlerForTest(t, lister))

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/activity?page=2", nil))

	if lister.lastFil.Limit != service.DefaultActivityPageSize {
		t.Fatalf("limit = %d, want %d", lister.lastFil.Limit, service.DefaultActivityPageSize)
	}
	if lister.lastFil.Offset != service.DefaultActivityPageSize {
		t.Fatalf("offset = %d, want %d", lister.lastFil.Offset, service.DefaultActivityPageSize)
	}
}

func TestActivityListParsesFilters(t *testing.T) {
	lister := &recordingActivityLister{}
	r := activityTestRouter(newActivityHandlerForTest(t, lister))

	req := httptest.NewRequest(http.MethodGet, "/admin/activity?action=tool.create&entity_type=tool&tool_id=7&from=2026-01-01&to=2026-01-31", nil)
	r.ServeHTTP(httptest.NewRecorder(), req)

	if lister.lastFil.Action != "tool.create" {
		t.Fatalf("action = %q", lister.lastFil.Action)
	}
	if lister.lastFil.EntityType != "tool" {
		t.Fatalf("entity_type = %q", lister.lastFil.EntityType)
	}
	if lister.lastFil.ToolID == nil || *lister.lastFil.ToolID != 7 {
		t.Fatalf("tool_id not parsed: %v", lister.lastFil.ToolID)
	}
	if lister.lastFil.From == nil || lister.lastFil.To == nil {
		t.Fatalf("date range not parsed: from=%v to=%v", lister.lastFil.From, lister.lastFil.To)
	}
}

func TestActivityListInvalidToolIDIgnored(t *testing.T) {
	lister := &recordingActivityLister{}
	r := activityTestRouter(newActivityHandlerForTest(t, lister))

	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/admin/activity?tool_id=notanumber", nil))
	if lister.lastFil.ToolID != nil {
		t.Fatalf("invalid tool_id should be ignored, got %v", lister.lastFil.ToolID)
	}
}

func TestActivityListPaginationLinks(t *testing.T) {
	lister := &recordingActivityLister{total: 500}
	r := activityTestRouter(newActivityHandlerForTest(t, lister))

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/activity?page=2&action=tool.create", nil))
	body := rec.Body.String()

	if !strings.Contains(body, "Sebelumnya") {
		t.Fatalf("missing prev link: %s", body)
	}
	if !strings.Contains(body, "Berikutnya") {
		t.Fatalf("missing next link: %s", body)
	}
	// Filter must be preserved in the page links.
	if !strings.Contains(body, "action=tool.create") {
		t.Fatalf("page links should preserve action filter: %s", body)
	}
}

func TestActivityListNeverRendersSecrets(t *testing.T) {
	// Even if a (buggy) row somehow carried a secret-looking value, the audit
	// view only renders allowlisted columns: actor/action/entity/tool/IP.
	lister := &recordingActivityLister{
		rows: []model.ActivityLog{
			{ID: 1, ActorType: "admin", Action: "token.create", MetadataJSON: strPtrSim(`{"token":"tbpbj_secret_plaintext"}`), UserAgent: strPtrSim("agent"), CreatedAt: time.Now()},
		},
		total: 1,
	}
	r := activityTestRouter(newActivityHandlerForTest(t, lister))

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/activity", nil))
	body := rec.Body.String()

	if strings.Contains(body, "tbpbj_secret_plaintext") {
		t.Fatalf("activity view leaked metadata secret: %s", body)
	}
}

func TestActivityListShowsErrorWithoutLeakingDetail(t *testing.T) {
	lister := &recordingActivityLister{failError: true}
	r := activityTestRouter(newActivityHandlerForTest(t, lister))

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/activity", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "context canceled") {
		t.Fatalf("raw error leaked to client: %s", rec.Body.String())
	}
}
