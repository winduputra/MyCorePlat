package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/winduputra/MyCorePlat/internal/model"
	"github.com/winduputra/MyCorePlat/internal/service"
)

// fakeToolService is a lightweight in-memory ToolService for handler tests.
type fakeToolService struct {
	tools      map[uint64]*model.Tool
	bySlug     map[string]uint64
	nextID     uint64
	createErr  error
	updateErr  error
	deleteErr  error
	listErr    error
	lastInput  service.ToolInput
	createCall int
	updateCall int
	deleteCall int
}

func newFakeToolService() *fakeToolService {
	return &fakeToolService{
		tools:  map[uint64]*model.Tool{},
		bySlug: map[string]uint64{},
		nextID: 0,
	}
}

func (f *fakeToolService) List(_ context.Context) ([]model.Tool, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]model.Tool, 0, len(f.tools))
	for _, t := range f.tools {
		out = append(out, *t)
	}
	return out, nil
}

func (f *fakeToolService) Get(_ context.Context, id uint64) (*model.Tool, error) {
	t, ok := f.tools[id]
	if !ok {
		return nil, service.ErrToolNotFound
	}
	copied := *t
	return &copied, nil
}

func (f *fakeToolService) Create(_ context.Context, in service.ToolInput) (*model.Tool, error) {
	f.createCall++
	f.lastInput = in
	if f.createErr != nil {
		return nil, f.createErr
	}
	if _, exists := f.bySlug[in.Slug]; exists {
		return nil, service.ErrDuplicateSlug
	}
	f.nextID++
	t := &model.Tool{ID: f.nextID, Slug: in.Slug, Name: in.Name, Status: in.Status, AccessType: in.AccessType, UpstreamURL: in.UpstreamURL, HealthcheckPath: in.HealthcheckPath}
	f.tools[t.ID] = t
	f.bySlug[t.Slug] = t.ID
	return t, nil
}

func (f *fakeToolService) Update(_ context.Context, id uint64, in service.ToolInput) (*model.Tool, error) {
	f.updateCall++
	f.lastInput = in
	if f.updateErr != nil {
		return nil, f.updateErr
	}
	t, ok := f.tools[id]
	if !ok {
		return nil, service.ErrToolNotFound
	}
	t.Slug = in.Slug
	t.Name = in.Name
	return t, nil
}

func (f *fakeToolService) Delete(_ context.Context, id uint64) error {
	f.deleteCall++
	if f.deleteErr != nil {
		return f.deleteErr
	}
	if _, ok := f.tools[id]; !ok {
		return service.ErrToolNotFound
	}
	delete(f.tools, id)
	return nil
}

func newToolsTestRouter(t *testing.T, h *AdminToolsHandler) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/admin/tools", h.List)
	r.GET("/admin/tools/new", h.New)
	r.POST("/admin/tools", h.Create)
	r.GET("/admin/tools/:id/edit", h.Edit)
	r.POST("/admin/tools/:id", h.Update)
	r.POST("/admin/tools/:id/delete", h.Delete)
	return r
}

func newToolsHandler(t *testing.T, svc ToolService) *AdminToolsHandler {
	t.Helper()
	h, err := NewAdminToolsHandler(svc, AdminToolsOptions{})
	if err != nil {
		t.Fatalf("NewAdminToolsHandler: %v", err)
	}
	return h
}

// TestToolsListRenders asserts the list page renders the "Tambah Tool" affordance
// and the empty-state when there are no tools.
func TestToolsListRenders(t *testing.T) {
	h := newToolsHandler(t, newFakeToolService())
	r := newToolsTestRouter(t, h)

	req := httptest.NewRequest(http.MethodGet, "/admin/tools", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Tambah Tool") {
		t.Error("list page missing 'Tambah Tool' link")
	}
	if !strings.Contains(body, "Belum ada tool") {
		t.Error("list page missing empty-state text")
	}
}

// TestToolsListShowsSeedData asserts seeded tools appear in the table.
func TestToolsListShowsSeedData(t *testing.T) {
	svc := newFakeToolService()
	svc.tools[1] = &model.Tool{ID: 1, Slug: "compressor", Name: "Image Compressor", Status: "active", AccessType: "public", UpstreamURL: "http://compressor:8000"}
	svc.bySlug["compressor"] = 1
	h := newToolsHandler(t, svc)
	r := newToolsTestRouter(t, h)

	req := httptest.NewRequest(http.MethodGet, "/admin/tools", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "compressor") || !strings.Contains(body, "Image Compressor") {
		t.Errorf("list page missing seeded tool data; body=%s", body)
	}
}

// TestToolsNewRendersForm asserts the create form renders with defaults.
func TestToolsNewRendersForm(t *testing.T) {
	h := newToolsHandler(t, newFakeToolService())
	r := newToolsTestRouter(t, h)

	req := httptest.NewRequest(http.MethodGet, "/admin/tools/new", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `action="/admin/tools"`) {
		t.Error("new form action should be /admin/tools")
	}
	if !strings.Contains(body, "name=\"slug\"") {
		t.Error("new form missing slug input")
	}
}

// TestToolsCreateRedirectsOnSuccess asserts a valid create redirects to the
// edit page (303) and calls the service exactly once.
func TestToolsCreateRedirectsOnSuccess(t *testing.T) {
	svc := newFakeToolService()
	h := newToolsHandler(t, svc)
	r := newToolsTestRouter(t, h)

	form := url.Values{
		"slug":             {"compressor"},
		"name":             {"Image Compressor"},
		"upstream_url":     {"http://compressor:8000"},
		"healthcheck_path": {"/health"},
		"access_type":      {"public"},
		"status":           {"draft"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/tools", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body=%s", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "/admin/tools/") {
		t.Errorf("Location = %q, want /admin/tools/{id}/edit", loc)
	}
	if svc.createCall != 1 {
		t.Errorf("createCall = %d, want 1", svc.createCall)
	}
	if svc.lastInput.Slug != "compressor" {
		t.Errorf("service received slug %q, want compressor", svc.lastInput.Slug)
	}
}

// TestToolsCreateDuplicateSlugRendersError asserts a duplicate slug yields 400
// and a hint message rather than a redirect.
func TestToolsCreateDuplicateSlugRendersError(t *testing.T) {
	svc := newFakeToolService()
	svc.createErr = service.ErrDuplicateSlug
	h := newToolsHandler(t, svc)
	r := newToolsTestRouter(t, h)

	form := url.Values{
		"slug":             {"dup"},
		"name":             {"Dup"},
		"upstream_url":     {"http://dup:8000"},
		"healthcheck_path": {"/health"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/tools", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "slug") {
		t.Error("error page should mention the slug problem")
	}
}

// TestToolsCreateInvalidUpstreamRendersError asserts an SSRF rejection surfaces
// as a 400 with a clear message.
func TestToolsCreateInvalidUpstreamRendersError(t *testing.T) {
	svc := newFakeToolService()
	svc.createErr = service.ErrInvalidUpstream
	h := newToolsHandler(t, svc)
	r := newToolsTestRouter(t, h)

	form := url.Values{
		"slug":             {"evil"},
		"name":             {"Evil"},
		"upstream_url":     {"https://example.com"},
		"healthcheck_path": {"/health"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/tools", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "upstream") {
		t.Error("error page should mention upstream URL")
	}
}

// TestToolsEditNotFound asserts editing a missing tool returns 404.
func TestToolsEditNotFound(t *testing.T) {
	h := newToolsHandler(t, newFakeToolService())
	r := newToolsTestRouter(t, h)

	req := httptest.NewRequest(http.MethodGet, "/admin/tools/999/edit", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

// TestToolsEditRendersExisting asserts the edit form is populated with the
// stored tool.
func TestToolsEditRendersExisting(t *testing.T) {
	svc := newFakeToolService()
	svc.tools[3] = &model.Tool{ID: 3, Slug: "existing", Name: "Existing Tool", Status: "draft", AccessType: "public", UpstreamURL: "http://existing:8000", HealthcheckPath: "/health"}
	svc.bySlug["existing"] = 3
	h := newToolsHandler(t, svc)
	r := newToolsTestRouter(t, h)

	req := httptest.NewRequest(http.MethodGet, "/admin/tools/3/edit", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Existing Tool") {
		t.Error("edit form missing existing tool name")
	}
	if !strings.Contains(body, `action="/admin/tools/3"`) {
		t.Error("edit form action should be /admin/tools/3")
	}
}

// TestToolsUpdateRedirectsOnSuccess asserts a valid update redirects (303).
func TestToolsUpdateRedirectsOnSuccess(t *testing.T) {
	svc := newFakeToolService()
	svc.tools[2] = &model.Tool{ID: 2, Slug: "upd", Name: "Before"}
	svc.bySlug["upd"] = 2
	h := newToolsHandler(t, svc)
	r := newToolsTestRouter(t, h)

	form := url.Values{
		"slug":             {"upd"},
		"name":             {"After"},
		"upstream_url":     {"http://upd:8000"},
		"healthcheck_path": {"/health"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/tools/2", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", w.Code)
	}
	if svc.updateCall != 1 {
		t.Errorf("updateCall = %d, want 1", svc.updateCall)
	}
	if svc.lastInput.Name != "After" {
		t.Errorf("service received name %q, want After", svc.lastInput.Name)
	}
}

// TestToolsUpdateNotFound asserts updating a missing tool returns 404.
func TestToolsUpdateNotFound(t *testing.T) {
	h := newToolsHandler(t, newFakeToolService())
	r := newToolsTestRouter(t, h)

	form := url.Values{"slug": {"x"}, "name": {"X"}, "upstream_url": {"http://x:8000"}, "healthcheck_path": {"/health"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/tools/999", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

// TestToolsDeleteHTMXReturnsEmpty asserts an HTMX delete returns 200 with an
// empty body so hx-swap outerHTML removes the row.
func TestToolsDeleteHTMXReturnsEmpty(t *testing.T) {
	svc := newFakeToolService()
	svc.tools[4] = &model.Tool{ID: 4, Slug: "del", Name: "Del"}
	svc.bySlug["del"] = 4
	h := newToolsHandler(t, svc)
	r := newToolsTestRouter(t, h)

	req := httptest.NewRequest(http.MethodPost, "/admin/tools/4/delete", nil)
	req.Header.Set("HX-Request", "true")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Errorf("HTMX delete body should be empty, got %q", w.Body.String())
	}
	if svc.deleteCall != 1 {
		t.Errorf("deleteCall = %d, want 1", svc.deleteCall)
	}
}

// TestToolsDeletePlainRedirects asserts a non-HTMX delete redirects to the list.
func TestToolsDeletePlainRedirects(t *testing.T) {
	svc := newFakeToolService()
	svc.tools[5] = &model.Tool{ID: 5, Slug: "del2", Name: "Del2"}
	svc.bySlug["del2"] = 5
	h := newToolsHandler(t, svc)
	r := newToolsTestRouter(t, h)

	req := httptest.NewRequest(http.MethodPost, "/admin/tools/5/delete", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/admin/tools" {
		t.Errorf("Location = %q, want /admin/tools", loc)
	}
}

// TestToolsDeleteNotFound asserts deleting a missing tool returns 404.
func TestToolsDeleteNotFound(t *testing.T) {
	h := newToolsHandler(t, newFakeToolService())
	r := newToolsTestRouter(t, h)

	req := httptest.NewRequest(http.MethodPost, "/admin/tools/999/delete", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}
