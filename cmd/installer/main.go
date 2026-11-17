// Command installer runs the Tool Installer service.
//
// The installer is the ONLY component that talks to the Docker Engine API.
// It runs as its own container, joins the internal tool-installer network and
// exposes a small authenticated HTTP API that the Core admin dashboard calls
// when an operator uploads a tool package. Core itself never receives the
// Docker socket.
//
// Authentication is a shared bearer token (INSTALLER_TOKEN / INSTALLER_TOKEN_FILE)
// compared in constant time. The service is expected to listen only on the
// internal network; it must never be published to the internet.
package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/winduputra/MyCorePlat/internal/installer"
	"github.com/winduputra/MyCorePlat/internal/repository"
	"github.com/winduputra/MyCorePlat/internal/service"
)

const (
	defaultAddr            = ":8090"
	defaultMaxUploadBytes  = 64 << 20
	defaultHealthTimeout   = 90 * time.Second
	defaultMemoryLimitMiB  = 512
	defaultCPULimit        = 1.0
	defaultPidsLimit       = 128
	shutdownTimeoutSeconds = 10
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		if err := healthcheck(); err != nil {
			fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		log.Fatalf("installer: %v", err)
	}
}

// healthcheck probes the local health endpoint for the container healthcheck.
// It reads only INSTALLER_ADDR and prints no configuration.
func healthcheck() error {
	addr := strings.TrimSpace(os.Getenv("INSTALLER_ADDR"))
	if addr == "" {
		addr = defaultAddr
	}
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + addr + "/health")
	if err != nil {
		return errors.New("health endpoint unreachable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health endpoint returned status %d", resp.StatusCode)
	}
	return nil
}

func run() error {
	settings, err := loadSettings()
	if err != nil {
		return err
	}

	db, err := repository.Open(context.Background(), settings.databaseDSN, repository.DefaultPoolSettings())
	if err != nil {
		return err
	}
	defer repository.Close(db)

	toolRepo := repository.NewToolRepository(db)
	// The allowlist is intentionally empty here: the installer registers the
	// upstream http://<slug>:<port> that it will run on the internal tools
	// network. Core re-validates on every connection anyway.
	toolSvc := service.NewToolService(toolRepo, service.NewUpstreamAllowlist(settings.allowedHosts...))
	registrar := installer.NewServiceToolRegistrar(toolSvc, toolRepo)
	records := installer.NewGormInstallRecordStore(db)

	ctx := context.Background()
	imageBuilder, err := installer.NewDockerImageBuilder(ctx)
	if err != nil {
		return fmt.Errorf("docker image builder: %w", err)
	}
	containerRunner, err := installer.NewDockerContainerRunner(ctx)
	if err != nil {
		return fmt.Errorf("docker container runner: %w", err)
	}
	secrets := installer.NewFileSecretProvisioner(settings.hmacKeysDir)

	engine, err := installer.New(imageBuilder, containerRunner, secrets, registrar, records, installer.Options{
		Network:         settings.toolNetwork,
		HMACKeysDir:     settings.hmacKeysDir,
		HMACKeysHostDir: settings.hmacKeysHostDir,
		WorkDir:         settings.workDir,
		HealthTimeout:   settings.healthTimeout,
		MemoryLimitMiB:  settings.memoryLimitMiB,
		CPULimit:        settings.cpuLimit,
		PidsLimit:       settings.pidsLimit,
	})
	if err != nil {
		return fmt.Errorf("installer engine: %w", err)
	}

	handler := newServer(engine, settings)
	srv := &http.Server{
		Addr:              settings.addr,
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("installer: listening on %s (tool network=%s)", settings.addr, settings.toolNetwork)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	stopCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-errCh:
		return err
	case <-stopCtx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeoutSeconds*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	log.Print("installer: shutdown complete")
	return nil
}

type settings struct {
	addr            string
	token           string
	databaseDSN     string
	toolNetwork     string
	hmacKeysDir     string
	hmacKeysHostDir string
	workDir         string
	maxUploadBytes  int64
	allowedHosts    []string
	healthTimeout   time.Duration
	memoryLimitMiB  int
	cpuLimit        float64
	pidsLimit       int
}

func loadSettings() (*settings, error) {
	s := &settings{
		addr:            getEnv("INSTALLER_ADDR", defaultAddr),
		toolNetwork:     getEnv("INSTALLER_TOOL_NETWORK", "tools"),
		hmacKeysDir:     getEnv("TOOL_HMAC_KEYS_DIR", "/run/secrets/tool-hmac"),
		hmacKeysHostDir: getEnv("INSTALLER_HMAC_KEYS_HOST_DIR", ""),
		workDir:         getEnv("INSTALLER_WORK_DIR", "/tmp/installer"),
		maxUploadBytes:  defaultMaxUploadBytes,
		healthTimeout:   defaultHealthTimeout,
		memoryLimitMiB:  defaultMemoryLimitMiB,
		cpuLimit:        defaultCPULimit,
		pidsLimit:       defaultPidsLimit,
	}

	token, err := loadSecret("INSTALLER_TOKEN_FILE", "INSTALLER_TOKEN")
	if err != nil {
		return nil, err
	}
	s.token = token

	dsn, err := loadDSN()
	if err != nil {
		return nil, err
	}
	s.databaseDSN = dsn

	if raw := strings.TrimSpace(os.Getenv("INSTALLER_MAX_UPLOAD_BYTES")); raw != "" {
		value, parseErr := strconv.ParseInt(raw, 10, 64)
		if parseErr != nil || value <= 0 {
			return nil, fmt.Errorf("invalid INSTALLER_MAX_UPLOAD_BYTES %q", raw)
		}
		s.maxUploadBytes = value
	}
	// The installer registers tools, and registration validates the upstream
	// hostname against an allowlist. The installer therefore needs the same
	// allowlist as Core; copy it from INSTALLER_UPSTREAM_ALLOWED_HOSTS.
	for _, host := range strings.Split(os.Getenv("INSTALLER_UPSTREAM_ALLOWED_HOSTS"), ",") {
		if trimmed := strings.TrimSpace(host); trimmed != "" {
			s.allowedHosts = append(s.allowedHosts, trimmed)
		}
	}
	if raw := strings.TrimSpace(os.Getenv("INSTALLER_HEALTH_TIMEOUT_SECONDS")); raw != "" {
		value, parseErr := strconv.Atoi(raw)
		if parseErr != nil || value <= 0 {
			return nil, fmt.Errorf("invalid INSTALLER_HEALTH_TIMEOUT_SECONDS %q", raw)
		}
		s.healthTimeout = time.Duration(value) * time.Second
	}
	if raw := strings.TrimSpace(os.Getenv("INSTALLER_MEMORY_LIMIT_MIB")); raw != "" {
		value, parseErr := strconv.Atoi(raw)
		if parseErr != nil || value <= 0 {
			return nil, fmt.Errorf("invalid INSTALLER_MEMORY_LIMIT_MIB %q", raw)
		}
		s.memoryLimitMiB = value
	}
	if raw := strings.TrimSpace(os.Getenv("INSTALLER_CPU_LIMIT")); raw != "" {
		value, parseErr := strconv.ParseFloat(raw, 64)
		if parseErr != nil || value <= 0 {
			return nil, fmt.Errorf("invalid INSTALLER_CPU_LIMIT %q", raw)
		}
		s.cpuLimit = value
	}
	if raw := strings.TrimSpace(os.Getenv("INSTALLER_PIDS_LIMIT")); raw != "" {
		value, parseErr := strconv.Atoi(raw)
		if parseErr != nil || value <= 0 {
			return nil, fmt.Errorf("invalid INSTALLER_PIDS_LIMIT %q", raw)
		}
		s.pidsLimit = value
	}

	return s, nil
}

func loadSecret(fileKey, envKey string) (string, error) {
	if path := strings.TrimSpace(os.Getenv(fileKey)); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", fileKey, err)
		}
		value := strings.TrimSpace(string(data))
		if value == "" {
			return "", fmt.Errorf("%s %q is empty", fileKey, path)
		}
		return value, nil
	}
	if value := strings.TrimSpace(os.Getenv(envKey)); value != "" {
		return value, nil
	}
	return "", fmt.Errorf("installer token is not configured: set %s or %s", fileKey, envKey)
}

func loadDSN() (string, error) {
	if path := strings.TrimSpace(os.Getenv("DB_DSN_FILE")); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read DB_DSN_FILE: %w", err)
		}
		value := strings.TrimSpace(string(data))
		if value == "" {
			return "", fmt.Errorf("DB_DSN_FILE %q is empty", path)
		}
		return value, nil
	}
	if value := strings.TrimSpace(os.Getenv("DB_DSN")); value != "" {
		return value, nil
	}
	return "", errors.New("database DSN is not configured: set DB_DSN_FILE or DB_DSN")
}

func getEnv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

type installEngine interface {
	Install(ctx context.Context, req installer.InstallRequest) (*installer.InstallRecord, error)
	Uninstall(ctx context.Context, slug string) error
	SetToolStatus(ctx context.Context, slug string, status string) error
	Record(ctx context.Context, slug string) (*installer.InstallRecord, error)
	Records(ctx context.Context) ([]installer.InstallRecord, error)
}

func newServer(engine installEngine, settings *settings) http.Handler {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "installer"})
	})

	auth := requireToken(settings.token)

	v1 := router.Group("/v1", auth)
	v1.POST("/tools", handleInstall(engine, settings))
	v1.GET("/tools", handleList(engine))
	v1.GET("/tools/:slug", handleGet(engine))
	v1.POST("/tools/:slug/enable", handleSetStatus(engine, "active"))
	v1.POST("/tools/:slug/disable", handleSetStatus(engine, "disabled"))
	v1.DELETE("/tools/:slug", handleUninstall(engine))

	return router
}

func requireToken(expected string) gin.HandlerFunc {
	return func(c *gin.Context) {
		supplied := bearerToken(c.GetHeader("Authorization"))
		if supplied == "" || subtle.ConstantTimeCompare([]byte(supplied), []byte(expected)) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.Next()
	}
}

func handleInstall(engine installEngine, settings *settings) gin.HandlerFunc {
	return func(c *gin.Context) {
		limited := http.MaxBytesReader(c.Writer, c.Request.Body, settings.maxUploadBytes)
		body, err := io.ReadAll(limited)
		if err != nil {
			writeError(c, http.StatusRequestEntityTooLarge, "package_too_large", "paket melebihi batas ukuran")
			return
		}

		adminID, _ := strconv.ParseUint(c.PostForm("admin_id"), 10, 64)
		req := installer.InstallRequest{PackageBytes: body, AdminID: adminID}

		record, err := engine.Install(c.Request.Context(), req)
		if err != nil {
			writeInstallError(c, err)
			return
		}
		c.JSON(http.StatusCreated, record)
	}
}

func handleList(engine installEngine) gin.HandlerFunc {
	return func(c *gin.Context) {
		records, err := engine.Records(c.Request.Context())
		if err != nil {
			writeError(c, http.StatusInternalServerError, "internal", "gagal membaca daftar tool")
			return
		}
		c.JSON(http.StatusOK, gin.H{"installations": records})
	}
}

func handleGet(engine installEngine) gin.HandlerFunc {
	return func(c *gin.Context) {
		record, err := engine.Record(c.Request.Context(), c.Param("slug"))
		if err != nil {
			writeInstallError(c, err)
			return
		}
		if record == nil {
			writeError(c, http.StatusNotFound, "not_found", "tool tidak ditemukan")
			return
		}
		c.JSON(http.StatusOK, record)
	}
}

func handleSetStatus(engine installEngine, status string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := engine.SetToolStatus(c.Request.Context(), c.Param("slug"), status); err != nil {
			writeInstallError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"slug": c.Param("slug"), "status": status})
	}
}

func handleUninstall(engine installEngine) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := engine.Uninstall(c.Request.Context(), c.Param("slug")); err != nil {
			writeInstallError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"slug": c.Param("slug"), "status": "removed"})
	}
}

func writeInstallError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, installer.ErrPackageInvalid):
		writeError(c, http.StatusBadRequest, "package_invalid", "paket tidak valid")
	case errors.Is(err, installer.ErrInvalidRequest):
		writeError(c, http.StatusBadRequest, "invalid_request", "permintaan tidak valid")
	case errors.Is(err, installer.ErrConflict):
		writeError(c, http.StatusConflict, "conflict", "tool dengan slug ini sudah terpasang")
	case errors.Is(err, installer.ErrNotInstalled):
		writeError(c, http.StatusNotFound, "not_found", "tool tidak ditemukan")
	case errors.Is(err, installer.ErrLifecycleBusy):
		writeError(c, http.StatusConflict, "busy", "operasi lain sedang berjalan")
	case errors.Is(err, installer.ErrBuildFailed):
		writeError(c, http.StatusUnprocessableEntity, "build_failed", "gagal membangun image")
	case errors.Is(err, installer.ErrRunFailed):
		writeError(c, http.StatusUnprocessableEntity, "run_failed", "gagal menjalankan container")
	case errors.Is(err, installer.ErrUnhealthy):
		writeError(c, http.StatusUnprocessableEntity, "unhealthy", "tool tidak lolos health check")
	case errors.Is(err, installer.ErrRegistrationFailed):
		writeError(c, http.StatusUnprocessableEntity, "registration_failed", "gagal mendaftarkan tool")
	default:
		writeError(c, http.StatusInternalServerError, "internal", "terjadi kesalahan internal")
	}
}

func writeError(c *gin.Context, status int, code, message string) {
	c.AbortWithStatusJSON(status, gin.H{"success": false, "error": code, "message": message})
}

func bearerToken(header string) string {
	const prefix = "bearer "
	trimmed := strings.TrimSpace(header)
	if len(trimmed) <= len(prefix) {
		return ""
	}
	if !strings.EqualFold(trimmed[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(trimmed[len(prefix):])
}
