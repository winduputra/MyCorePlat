package handlers

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/winduputra/MyCorePlat/internal/model"
)

type fakeCatalogTools struct {
	tools []model.Tool
	err   error
}

func (f fakeCatalogTools) List(ctx context.Context) ([]model.Tool, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.tools, nil
}

func activePublicTool(id uint64, slug, name, desc string, order int) model.Tool {
	d := desc
	return model.Tool{
		ID:              id,
		Slug:            slug,
		Name:            name,
		Description:     &d,
		AccessType:      model.ToolAccessPublic,
		Status:          model.ToolStatusActive,
		UpstreamURL:     "http://" + slug + ":8000",
		HealthcheckPath: "/health",
		DisplayOrder:    order,
	}
}

func mustCatalog(t *testing.T, tools CatalogTools) *CatalogHandler {
	t.Helper()
	h, err := NewCatalogHandler(tools)
	if err != nil {
		t.Fatalf("new catalog handler: %v", err)
	}
	return h
}

func newCatalogRouter(h *CatalogHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/", h.Serve)
	return r
}

func TestCatalogListsOnlyActivePublicTools(t *testing.T) {
	draft := activePublicTool(2, "draft-tool", "Draft Tool", "not ready", 2)
	draft.Status = model.ToolStatusDraft

	disabled := activePublicTool(3, "disabled-tool", "Disabled Tool", "off", 3)
	disabled.Status = model.ToolStatusDisabled

	tokenTool := activePublicTool(4, "token-tool", "Token Tool", "needs token", 4)
	tokenTool.AccessType = model.ToolAccessToken

	deleted := activePublicTool(5, "deleted-tool", "Deleted Tool", "gone", 5)
	deletedAt := time.Now()
	deleted.DeletedAt = &deletedAt

	handler := mustCatalog(t, fakeCatalogTools{tools: []model.Tool{
		activePublicTool(1, "pdf-compressor", "PDF Compressor", "Compress PDF files", 1),
		draft,
		disabled,
		tokenTool,
		deleted,
	}})

	w := performRequest(newCatalogRouter(handler), http.MethodGet, "/")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()

	if !strings.Contains(body, "PDF Compressor") {
		t.Fatal("active public tool must be listed")
	}
	for _, hidden := range []string{"Draft Tool", "Disabled Tool", "Token Tool", "Deleted Tool"} {
		if strings.Contains(body, hidden) {
			t.Fatalf("%q must not appear in the public catalog", hidden)
		}
	}
}

func TestCatalogLinksToGatewayPath(t *testing.T) {
	handler := mustCatalog(t, fakeCatalogTools{tools: []model.Tool{
		activePublicTool(1, "pdf-compressor", "PDF Compressor", "Compress PDF files", 1),
	}})

	w := performRequest(newCatalogRouter(handler), http.MethodGet, "/")

	if !strings.Contains(w.Body.String(), `href="/t/pdf-compressor/"`) {
		t.Fatalf("catalog must link to the gateway path, got: %s", w.Body.String())
	}
}

func TestCatalogShowsEmptyState(t *testing.T) {
	handler := mustCatalog(t, fakeCatalogTools{})
	w := performRequest(newCatalogRouter(handler), http.MethodGet, "/")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Belum ada tool") {
		t.Fatalf("expected an empty-state message, got: %s", w.Body.String())
	}
}

func TestCatalogSurvivesRepositoryError(t *testing.T) {
	handler := mustCatalog(t, fakeCatalogTools{err: context.DeadlineExceeded})
	w := performRequest(newCatalogRouter(handler), http.MethodGet, "/")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (public page must not leak failure)", w.Code)
	}
	if strings.Contains(w.Body.String(), "deadline") {
		t.Fatal("internal error details must never be rendered")
	}
}

func TestCatalogNeverRendersUpstreamOrSensitiveFields(t *testing.T) {
	handler := mustCatalog(t, fakeCatalogTools{tools: []model.Tool{
		activePublicTool(1, "pdf-compressor", "PDF Compressor", "Compress PDF files", 1),
	}})
	w := performRequest(newCatalogRouter(handler), http.MethodGet, "/")
	body := w.Body.String()

	for _, forbidden := range []string{"http://pdf-compressor:8000", "manifest"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("public catalog must not expose %q", forbidden)
		}
	}
}

func TestCatalogOrderFollowsRepositoryOrder(t *testing.T) {
	handler := mustCatalog(t, fakeCatalogTools{tools: []model.Tool{
		activePublicTool(1, "first-tool", "AAA First", "one", 1),
		activePublicTool(2, "second-tool", "BBB Second", "two", 2),
	}})
	body := performRequest(newCatalogRouter(handler), http.MethodGet, "/").Body.String()

	if strings.Index(body, "AAA First") > strings.Index(body, "BBB Second") {
		t.Fatal("catalog must preserve repository ordering")
	}
}
