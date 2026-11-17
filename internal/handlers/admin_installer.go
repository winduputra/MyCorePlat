package handlers

import (
	"context"
	"errors"
	"html/template"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/winduputra/MyCorePlat/internal/installerclient"
	"github.com/winduputra/MyCorePlat/internal/middleware"
	"github.com/winduputra/MyCorePlat/internal/model"
	"github.com/winduputra/MyCorePlat/internal/service"
)

// InstallerClient is the subset of the installer HTTP client the manager UI
// needs. It is an interface so the handler can be tested without a live
// installer service.
type InstallerClient interface {
	Configured() bool
	Install(ctx context.Context, packageBytes []byte, adminID uint64) (*installerclient.Installation, error)
	List(ctx context.Context) ([]installerclient.Installation, error)
	Get(ctx context.Context, slug string) (*installerclient.Installation, error)
	Enable(ctx context.Context, slug string) error
	Disable(ctx context.Context, slug string) error
	Uninstall(ctx context.Context, slug string) error
}

// AdminInstallerOptions configures the installer management UI.
type AdminInstallerOptions struct {
	// MaxUploadBytes caps the ZIP size accepted from the browser before the
	// request is rejected. It must not exceed the installer's own limit.
	MaxUploadBytes int64
	// UploadTimeout bounds a build-and-run install request. Building an image
	// and starting a container is slow, so this is generous.
	UploadTimeout time.Duration
}

// AdminInstallerHandler serves the dynamic tool installer pages.
type AdminInstallerHandler struct {
	client         InstallerClient
	opts           AdminInstallerOptions
	tmpl           map[string]*template.Template
	activity       ActivityRecorder
	configured     bool
	configuredHint string
}

// NewAdminInstallerHandler builds the handler. A nil client (or an
// unconfigured one) is allowed: the pages still render but every action reports
// that the installer is not configured, rather than panicking.
func NewAdminInstallerHandler(client InstallerClient, opts AdminInstallerOptions) (*AdminInstallerHandler, error) {
	if opts.MaxUploadBytes <= 0 {
		opts.MaxUploadBytes = 64 << 20
	}
	if opts.UploadTimeout <= 0 {
		opts.UploadTimeout = 12 * time.Minute
	}
	funcs := adminTemplateFuncs()
	pages := map[string]string{
		"installer_list": "templates/pages/installer_list.html.tmpl",
	}
	tmpl := make(map[string]*template.Template, len(pages))
	for name, page := range pages {
		t, err := template.New(name).Funcs(funcs).ParseFS(templateFS,
			"templates/layouts/admin.html.tmpl",
			page,
		)
		if err != nil {
			return nil, err
		}
		tmpl[name] = t
	}
	return &AdminInstallerHandler{
		client:     client,
		opts:       opts,
		tmpl:       tmpl,
		configured: client != nil && client.Configured(),
	}, nil
}

// SetActivityRecorder attaches the audit recorder. Nil disables auditing.
func (h *AdminInstallerHandler) SetActivityRecorder(recorder ActivityRecorder) {
	h.activity = recorder
}

// installerListData is the view model for the installer page.
type installerListData struct {
	Title          string
	Configured     bool
	Installations  []installerclient.Installation
	Notice         string
	Error          string
	MaxUploadBytes int64
	CSRFToken      string
}

func (d *installerListData) setCSRFToken(token string) { d.CSRFToken = token }

// List renders the installed tools and the upload form.
func (h *AdminInstallerHandler) List(c *gin.Context) {
	data := installerListData{
		Title:          "Installer Tool",
		Configured:     h.configured,
		MaxUploadBytes: h.opts.MaxUploadBytes,
	}
	if !h.configured {
		data.Notice = "Layanan installer belum dikonfigurasi. Hubungi administrator sistem."
		h.render(c, http.StatusOK, data)
		return
	}
	installations, err := h.client.List(c.Request.Context())
	if err != nil {
		data.Error = installError(err)
		h.render(c, http.StatusOK, data)
		return
	}
	data.Installations = installations
	h.render(c, http.StatusOK, data)
}

// Create verifies the uploaded ZIP and streams it to the installer service.
func (h *AdminInstallerHandler) Create(c *gin.Context) {
	if !h.configured {
		h.render(c, http.StatusServiceUnavailable, installerListData{
			Title:      "Installer Tool",
			Configured: false,
			Error:      "layanan installer belum dikonfigurasi",
		})
		return
	}

	adminID, ok := middleware.AdminIDFromContext(c)
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// Bound the request so an oversized upload cannot exhaust memory. The
	// MaxBytesReader aborts the read and lets us return 413.
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, h.opts.MaxUploadBytes)
	fileHeader, err := c.FormFile("package")
	if err != nil {
		h.renderUploadError(c, http.StatusBadRequest, "file paket tidak ditemukan atau terlalu besar")
		return
	}
	if fileHeader.Size > h.opts.MaxUploadBytes {
		h.renderUploadError(c, http.StatusRequestEntityTooLarge, "ukuran paket melebihi batas")
		return
	}

	src, err := fileHeader.Open()
	if err != nil {
		h.renderUploadError(c, http.StatusBadRequest, "gagal membaca paket")
		return
	}
	defer src.Close()

	packageBytes, err := io.ReadAll(io.LimitReader(src, h.opts.MaxUploadBytes+1))
	if err != nil {
		h.renderUploadError(c, http.StatusBadRequest, "gagal membaca paket")
		return
	}
	if int64(len(packageBytes)) > h.opts.MaxUploadBytes {
		h.renderUploadError(c, http.StatusRequestEntityTooLarge, "ukuran paket melebihi batas")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), h.opts.UploadTimeout)
	defer cancel()

	inst, err := h.client.Install(ctx, packageBytes, adminID)
	if err != nil {
		h.renderUploadError(c, uploadStatus(err), installError(err))
		return
	}
	h.record(c, inst, "tool.install")
	h.renderList(c, http.StatusOK, "Tool berhasil diinstal. Aktifkan melalui tombol Aktifkan bila sudah siap.")
}

// Enable activates an installed tool.
func (h *AdminInstallerHandler) Enable(c *gin.Context) {
	h.lifecycle(c, "enable", "tool.enable", "Tool diaktifkan.")
}

// Disable deactivates an installed tool.
func (h *AdminInstallerHandler) Disable(c *gin.Context) {
	h.lifecycle(c, "disable", "tool.disable", "Tool dinonaktifkan.")
}

// Delete uninstalls a tool and removes its container, image, and secret.
func (h *AdminInstallerHandler) Delete(c *gin.Context) {
	slug := c.Param("slug")
	if !h.configured {
		h.renderUploadError(c, http.StatusServiceUnavailable, "layanan installer belum dikonfigurasi")
		return
	}
	if err := h.client.Uninstall(c.Request.Context(), slug); err != nil {
		h.renderUploadError(c, uploadStatus(err), installError(err))
		return
	}
	h.recordSlug(c, slug, "tool.uninstall")
	h.renderList(c, http.StatusOK, "Tool dihapus.")
}

func (h *AdminInstallerHandler) lifecycle(c *gin.Context, action, auditAction, notice string) {
	if !h.configured {
		h.renderUploadError(c, http.StatusServiceUnavailable, "layanan installer belum dikonfigurasi")
		return
	}
	slug := c.Param("slug")
	var err error
	switch action {
	case "enable":
		err = h.client.Enable(c.Request.Context(), slug)
	case "disable":
		err = h.client.Disable(c.Request.Context(), slug)
	}
	if err != nil {
		h.renderUploadError(c, uploadStatus(err), installError(err))
		return
	}
	h.recordSlug(c, slug, auditAction)
	h.renderList(c, http.StatusOK, notice)
}

func (h *AdminInstallerHandler) record(c *gin.Context, inst *installerclient.Installation, action string) {
	if h.activity == nil || inst == nil {
		return
	}
	entry := installerActivityEntry(c, action, inst.Slug)
	if inst.ToolID != 0 {
		entry.EntityID = &inst.ToolID
		entry.ToolID = &inst.ToolID
	}
	h.activity.Record(c.Request.Context(), entry)
}

func (h *AdminInstallerHandler) recordSlug(c *gin.Context, slug, action string) {
	if h.activity == nil {
		return
	}
	h.activity.Record(c.Request.Context(), installerActivityEntry(c, action, slug))
}

// installerActivityEntry builds an audit row for an installer action. Only the
// slug is recorded �?" never the package contents, image tag, or secret.
func installerActivityEntry(c *gin.Context, action, slug string) service.ActivityEntry {
	entry := service.ActivityEntry{
		ActorType:  model.ActorTypeAdmin,
		Action:     action,
		EntityType: service.EntityTypeTool,
		IPAddress:  clientAddr(c, nil),
		UserAgent:  c.Request.UserAgent(),
		Metadata:   map[string]any{"slug": slug},
	}
	if adminID, ok := middleware.AdminIDFromContext(c); ok {
		entry.ActorID = &adminID
	}
	return entry
}

func (h *AdminInstallerHandler) renderList(c *gin.Context, status int, notice string) {
	data := installerListData{
		Title:          "Installer Tool",
		Configured:     h.configured,
		Notice:         notice,
		MaxUploadBytes: h.opts.MaxUploadBytes,
	}
	installations, err := h.client.List(c.Request.Context())
	if err == nil {
		data.Installations = installations
	} else {
		data.Error = installError(err)
	}
	h.render(c, status, data)
}

func (h *AdminInstallerHandler) renderUploadError(c *gin.Context, status int, message string) {
	h.render(c, status, installerListData{
		Title:          "Installer Tool",
		Configured:     h.configured,
		Error:          message,
		MaxUploadBytes: h.opts.MaxUploadBytes,
	})
}

func (h *AdminInstallerHandler) render(c *gin.Context, status int, data installerListData) {
	set, ok := h.tmpl["installer_list"]
	if !ok {
		c.String(http.StatusInternalServerError, "render error")
		return
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.Status(status)
	if err := set.ExecuteTemplate(c.Writer, "installer_list", withCSRF(c, data)); err != nil {
		c.String(http.StatusInternalServerError, "render error")
	}
}

// installError converts a client error into an Indonesian operator message.
// The installer never returns secrets or internal paths, so its message is safe
// to surface.
func installError(err error) string {
	switch {
	case errors.Is(err, installerclient.ErrNotConfigured):
		return "layanan installer belum dikonfigurasi"
	case errors.Is(err, installerclient.ErrInvalidSlug):
		return "slug tool tidak valid"
	case errors.Is(err, installerclient.ErrNotFound):
		return "tool tidak ditemukan"
	case errors.Is(err, installerclient.ErrConflict):
		return "instalasi sedang berjalan atau tool sudah terpasang"
	case errors.Is(err, installerclient.ErrTooLarge):
		return "ukuran paket melebihi batas"
	case errors.Is(err, installerclient.ErrPackage):
		return "paket ditolak: " + stripErrorPrefix(err)
	case errors.Is(err, installerclient.ErrUnavailable):
		return "layanan installer tidak dapat dihubungi"
	default:
		return "instalasi gagal"
	}
}

// uploadStatus maps a client error to the HTTP status shown to the operator.
func uploadStatus(err error) int {
	switch {
	case errors.Is(err, installerclient.ErrTooLarge):
		return http.StatusRequestEntityTooLarge
	case errors.Is(err, installerclient.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, installerclient.ErrConflict):
		return http.StatusConflict
	case errors.Is(err, installerclient.ErrPackage), errors.Is(err, installerclient.ErrInvalidSlug):
		return http.StatusBadRequest
	case errors.Is(err, installerclient.ErrNotConfigured), errors.Is(err, installerclient.ErrUnavailable):
		return http.StatusServiceUnavailable
	default:
		return http.StatusBadGateway
	}
}

// stripErrorPrefix removes the internal sentinel prefix from a wrapped error so
// the operator sees only the human message.
func stripErrorPrefix(err error) string {
	msg := err.Error()
	if idx := strings.Index(msg, ": "); idx >= 0 {
		return msg[idx+2:]
	}
	return msg
}
