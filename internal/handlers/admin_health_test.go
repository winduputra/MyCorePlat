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

// fakeHealthReader returns a canned tool list.
type fakeHealthReader struct {
	tools []model.Tool
	err   error
}

func (f fakeHealthReader) List(_ context.Context) ([]model.Tool, error) {
	return f.tools, f.err
}

// fakeHealthSnapshotter returns canned latest checks.
type fakeHealthSnapshotter struct {
	latest map[uint64]*model.ToolHealthCheck
	err    error
}

func (f fakeHealthSnapshotter) LatestByTool(_ context.Context, _ []uint64) (map[uint64]*model.ToolHealthCheck, error) {
	return f.latest, f.err
}

func newHealthHandlerForTest(t *testing.T, tools HealthReader, health HealthSnapshotter) *AdminHealthHandler {
	t.Helper()
	h, err := NewAdminHealthHandler(tools, health)
	if err != nil {
		t.Fatalf("NewAdminHealthHandler: %v", err)
	}
	return h
}

func healthTestRouter(h *AdminHealthHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/admin/health", h.List)
	return r
}

func TestHealthListRendersStatusAndLatency(t *testing.T) {
	latency := 42
	tools := fakeHealthReader{tools: []model.Tool{{ID: 1, Name: "Image Compressor", Slug: "image-compressor"}}}
	snap := fakeHealthSnapshotter{latest: map[uint64]*model.ToolHealthCheck{
		1: {ToolID: 1, Status: model.HealthStatusHealthy, LatencyMS: &latency, CheckedAt: time.Now()},
	}}
	r := healthTestRouter(newHealthHandlerForTest(t, tools, snap))

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/health", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"Image Compressor", "image-compressor", "healthy", "42 ms"} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %q: %s", want, body)
		}
	}
}

func TestHealthListShowsNeverChecked(t *testing.T) {
	tools := fakeHealthReader{tools: []model.Tool{{ID: 2, Name: "Fresh", Slug: "fresh"}}}
	r := healthTestRouter(newHealthHandlerForTest(t, tools, fakeHealthSnapshotter{}))

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/health", nil))
	if !strings.Contains(rec.Body.String(), "belum diperiksa") {
		t.Fatalf("expected never-checked marker: %s", rec.Body.String())
	}
}

func TestHealthListRendersSafeReason(t *testing.T) {
	reason := service.HealthReasonConnectionFailed
	tools := fakeHealthReader{tools: []model.Tool{{ID: 3, Name: "Broken", Slug: "broken"}}}
	snap := fakeHealthSnapshotter{latest: map[uint64]*model.ToolHealthCheck{
		3: {ToolID: 3, Status: model.HealthStatusUnhealthy, ErrorMessage: &reason, CheckedAt: time.Now()},
	}}
	r := healthTestRouter(newHealthHandlerForTest(t, tools, snap))

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/health", nil))
	if !strings.Contains(rec.Body.String(), "connection failed") {
		t.Fatalf("expected safe reason: %s", rec.Body.String())
	}
}

func TestHealthListToolErrorIsGeneric(t *testing.T) {
	tools := fakeHealthReader{err: context.Canceled}
	r := healthTestRouter(newHealthHandlerForTest(t, tools, fakeHealthSnapshotter{}))

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/health", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "context canceled") {
		t.Fatalf("raw error leaked: %s", rec.Body.String())
	}
}
