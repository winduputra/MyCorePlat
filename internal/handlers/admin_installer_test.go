package handlers

import (
	"bytes"
	"context"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/winduputra/MyCorePlat/internal/installerclient"
)

// fakeInstallerClient records calls and returns canned results.
type fakeInstallerClient struct {
	configured bool

	installInst *installerclient.Installation
	installErr  error
	installBody []byte
	installCall int

	listInst []installerclient.Installation
	listErr  error

	enableErr    error
	disableErr   error
	uninstallErr error
	lastSlug     string
}

func (f *fakeInstallerClient) Configured() bool { return f.configured }

func (f *fakeInstallerClient) Install(_ context.Context, pkg []byte, _ uint64) (*installerclient.Installation, error) {
	f.installCall++
	f.installBody = pkg
	return f.installInst, f.installErr
}

func (f *fakeInstallerClient) List(_ context.Context) ([]installerclient.Installation, error) {
	return f.listInst, f.listErr
}

func (f *fakeInstallerClient) Get(_ context.Context, slug string) (*installerclient.Installation, error) {
	f.lastSlug = slug
	return nil, nil
}

func (f *fakeInstallerClient) Enable(_ context.Context, slug string) error {
	f.lastSlug = slug
	return f.enableErr
}

func (f *fakeInstallerClient) Disable(_ context.Context, slug string) error {
	f.lastSlug = slug
	return f.disableErr
}

func (f *fakeInstallerClient) Uninstall(_ context.Context, slug string) error {
	f.lastSlug = slug
	return f.uninstallErr
}

func newInstallerHandlerForTest(t *testing.T, client InstallerClient) *AdminInstallerHandler {
	t.Helper()
	h, err := NewAdminInstallerHandler(client, AdminInstallerOptions{
		MaxUploadBytes: 1 << 20,
		UploadTimeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewAdminInstallerHandler: %v", err)
	}
	return h
}

func installerTestRouter(h *AdminInstallerHandler, adminID uint64) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("auth_admin_id", adminID)
		c.Next()
	})
	r.GET("/admin/installer", h.List)
	r.POST("/admin/installer", h.Create)
	r.POST("/admin/installer/:slug/enable", h.Enable)
	r.POST("/admin/installer/:slug/disable", h.Disable)
	r.DELETE("/admin/installer/:slug", h.Delete)
	return r
}

func multipartPackage(t *testing.T, filename string, content []byte) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile("package", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf, w.FormDataContentType()
}

func TestInstallerListRendersInstalledTools(t *testing.T) {
	client := &fakeInstallerClient{
		configured: true,
		listInst:   []installerclient.Installation{{Slug: "pdf-compressor", Status: "installed", Version: "1.0.0"}},
	}
	r := installerTestRouter(newInstallerHandlerForTest(t, client), 1)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/installer", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "pdf-compressor") {
		t.Errorf("body missing installed tool slug")
	}
	if !strings.Contains(body, "name=\"csrf_token\"") {
		t.Errorf("upload form must carry a CSRF hidden field")
	}
}

func TestInstallerListUnconfiguredShowsNotice(t *testing.T) {
	r := installerTestRouter(newInstallerHandlerForTest(t, nil), 1)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/installer", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "belum dikonfigurasi") {
		t.Errorf("body should explain the installer is not configured")
	}
}

func TestInstallerCreateUploadsPackage(t *testing.T) {
	client := &fakeInstallerClient{
		configured:  true,
		installInst: &installerclient.Installation{Slug: "pdf-compressor", Status: "installed", ToolID: 9},
	}
	r := installerTestRouter(newInstallerHandlerForTest(t, client), 1)
	buf, ctype := multipartPackage(t, "tool.zip", []byte("PK\x03\x04zipdata"))
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/installer", buf)
	req.Header.Set("Content-Type", ctype)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	if client.installCall != 1 {
		t.Fatalf("install call count = %d", client.installCall)
	}
	if string(client.installBody) != "PK\x03\x04zipdata" {
		t.Errorf("forwarded package = %q", client.installBody)
	}
}

func TestInstallerCreateRejectsWithoutAdminContext(t *testing.T) {
	client := &fakeInstallerClient{configured: true}
	h := newInstallerHandlerForTest(t, client)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/admin/installer", h.Create)
	buf, ctype := multipartPackage(t, "tool.zip", []byte("x"))
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/installer", buf)
	req.Header.Set("Content-Type", ctype)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if client.installCall != 0 {
		t.Errorf("install must not be called without an admin context")
	}
}

func TestInstallerCreateRejectsMissingFile(t *testing.T) {
	client := &fakeInstallerClient{configured: true}
	r := installerTestRouter(newInstallerHandlerForTest(t, client), 1)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/installer", strings.NewReader("not multipart"))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=none")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if client.installCall != 0 {
		t.Errorf("install must not be called when the package is missing")
	}
}

func TestInstallerCreateMapsPackageError(t *testing.T) {
	client := &fakeInstallerClient{
		configured: true,
		installErr: installerclient.ErrPackage,
	}
	r := installerTestRouter(newInstallerHandlerForTest(t, client), 1)
	buf, ctype := multipartPackage(t, "tool.zip", []byte("badzip"))
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/installer", buf)
	req.Header.Set("Content-Type", ctype)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "ditolak") {
		t.Errorf("body should explain the package was rejected: %s", w.Body.String())
	}
}

func TestInstallerLifecycleCalls(t *testing.T) {
	client := &fakeInstallerClient{configured: true}
	r := installerTestRouter(newInstallerHandlerForTest(t, client), 1)

	for _, tc := range []struct {
		method, path, wantSlug string
	}{
		{http.MethodPost, "/admin/installer/pdf-compressor/enable", "pdf-compressor"},
		{http.MethodPost, "/admin/installer/pdf-compressor/disable", "pdf-compressor"},
		{http.MethodDelete, "/admin/installer/pdf-compressor", "pdf-compressor"},
	} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(tc.method, tc.path, nil)
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("%s %s status = %d", tc.method, tc.path, w.Code)
		}
		if client.lastSlug != tc.wantSlug {
			t.Errorf("%s: lastSlug = %q, want %q", tc.path, client.lastSlug, tc.wantSlug)
		}
	}
}

func TestInstallerLifecycleNotFound(t *testing.T) {
	client := &fakeInstallerClient{configured: true, uninstallErr: installerclient.ErrNotFound}
	r := installerTestRouter(newInstallerHandlerForTest(t, client), 1)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/admin/installer/missing-tool", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestInstallerErrorMapping(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{installerclient.ErrPackage, http.StatusBadRequest},
		{installerclient.ErrTooLarge, http.StatusRequestEntityTooLarge},
		{installerclient.ErrNotFound, http.StatusNotFound},
		{installerclient.ErrConflict, http.StatusConflict},
		{installerclient.ErrUnavailable, http.StatusServiceUnavailable},
		{installerclient.ErrNotConfigured, http.StatusServiceUnavailable},
		{errors.New("boom"), http.StatusBadGateway},
	}
	for _, tc := range cases {
		if got := uploadStatus(tc.err); got != tc.want {
			t.Errorf("uploadStatus(%v) = %d, want %d", tc.err, got, tc.want)
		}
	}
}
