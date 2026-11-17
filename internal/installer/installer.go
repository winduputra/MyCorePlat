package installer

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/winduputra/MyCorePlat/internal/model"
	"github.com/winduputra/MyCorePlat/pkg/tooldist"
)

// Options configures the installer orchestration.
type Options struct {
	// Network is the isolated Docker network tool containers join.
	Network string
	// HMACKeysDir is the directory where per-tool key files are written, as
	// seen by the installer process itself.
	HMACKeysDir string
	// HMACKeysHostDir is the SAME directory expressed as a path on the Docker
	// host. Tool containers bind-mount it, and the Docker daemon resolves bind
	// sources against the host filesystem, not the installer's namespace. When
	// empty it falls back to HMACKeysDir (correct only when the installer runs
	// directly on the host with an identical path).
	HMACKeysHostDir string
	// WorkDir is a scratch directory for extracted build contexts.
	WorkDir string
	// HealthTimeout is how long to wait for a new container to become healthy.
	HealthTimeout time.Duration
	// HealthPollInterval is the delay between health probes.
	HealthPollInterval time.Duration
	// MemoryLimitMiB, CPULimit and PidsLimit size each tool container.
	MemoryLimitMiB int
	CPULimit       float64
	PidsLimit      int
	// Now overrides the clock in tests.
	Now func() time.Time
}

// Installer coordinates the full tool lifecycle.
type Installer struct {
	builder   ImageBuilder
	runner    ContainerRunner
	secrets   SecretProvisioner
	registrar ToolRegistrar
	records   InstallRecordStore
	opts      Options

	// mu serialises lifecycle operations for one slug. A map of per-slug locks
	// would scale further, but a single mutex is sufficient for an internal
	// installer and is far easier to reason about.
	mu sync.Mutex
}

// New builds an Installer. All collaborators are required.
func New(builder ImageBuilder, runner ContainerRunner, secrets SecretProvisioner, registrar ToolRegistrar, records InstallRecordStore, opts Options) (*Installer, error) {
	if builder == nil || runner == nil || secrets == nil || registrar == nil || records == nil {
		return nil, fmt.Errorf("%w: missing collaborator", ErrInvalidRequest)
	}
	if opts.Network == "" || opts.HMACKeysDir == "" || opts.WorkDir == "" {
		return nil, fmt.Errorf("%w: network, hmac keys dir and work dir are required", ErrInvalidRequest)
	}
	if opts.HealthTimeout <= 0 {
		opts.HealthTimeout = 60 * time.Second
	}
	if opts.HealthPollInterval <= 0 {
		opts.HealthPollInterval = 2 * time.Second
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	// The work dir lives on a tmpfs in containers, so it may not exist yet.
	// Creating it here keeps every Install/Uninstall call self-sufficient.
	if err := os.MkdirAll(opts.WorkDir, 0o700); err != nil {
		return nil, fmt.Errorf("%w: create work dir: %v", ErrInvalidRequest, err)
	}
	return &Installer{builder: builder, runner: runner, secrets: secrets, registrar: registrar, records: records, opts: opts}, nil
}

// Install validates, builds, runs, and registers a tool package. On any failure
// after resources have been created it rolls those resources back so a failed
// install never leaves a half-built tool behind.
func (in *Installer) Install(ctx context.Context, req InstallRequest) (*InstallRecord, error) {
	in.mu.Lock()
	defer in.mu.Unlock()

	inspected, err := tooldist.Inspect(req.PackageBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPackageInvalid, err)
	}
	manifest := Manifest{
		ID: inspected.Manifest.ID, Name: inspected.Manifest.Name, Version: inspected.Manifest.Version,
		Description: inspected.Manifest.Description, Category: inspected.Manifest.Category,
		Access: inspected.Manifest.Access, Runtime: inspected.Manifest.Runtime,
		Upstream: inspected.Manifest.Upstream, Healthcheck: inspected.Manifest.Healthcheck,
		DisplayOrder: inspected.Manifest.DisplayOrder, Icon: inspected.Manifest.Icon,
		SchemaVersion: inspected.Manifest.SchemaVersion,
	}
	if !IsValidSlug(manifest.ID) {
		return nil, fmt.Errorf("%w: invalid slug", ErrPackageInvalid)
	}
	if !manifest.Healthy() {
		return nil, fmt.Errorf("%w: manifest has no healthcheck path", ErrPackageInvalid)

	}
	if existing, err := in.records.BySlug(ctx, manifest.ID); err == nil && existing != nil && existing.Status != model.ToolInstallFailed && existing.Status != model.ToolInstallRemoved {
		return nil, fmt.Errorf("%w: %s", ErrConflict, manifest.ID)
	}

	now := req.Now
	if now.IsZero() {
		now = in.opts.Now()
	}

	pkg := &Package{Slug: manifest.ID, Manifest: manifest, SHA256: inspected.PackageSHA256, Bytes: req.PackageBytes}

	rec := &InstallRecord{
		Slug:             manifest.ID,
		Status:           model.ToolInstallPending,
		Version:          manifest.Version,
		PackageSHA256:    pkg.SHA256,
		InstalledByAdmin: req.AdminID,
		CreatedAt:        now.UnixMilli(),
		UpdatedAt:        now.UnixMilli(),
	}
	if err := in.records.Create(ctx, rec); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRegistrationFailed, err)
	}

	// From here on every failure goes through rollback.
	buildDir, err := os.MkdirTemp(in.opts.WorkDir, "build-"+manifest.ID+"-")
	if err != nil {
		return in.fail(ctx, rec, "workdir", ErrBuildFailed, err)
	}
	defer os.RemoveAll(buildDir)

	if err := tooldist.Extract(req.PackageBytes, buildDir); err != nil {
		return in.fail(ctx, rec, "extract", ErrPackageInvalid, err)
	}

	rec.Status = model.ToolInstallBuilding
	rec.UpdatedAt = in.opts.Now().UnixMilli()
	_ = in.records.Update(ctx, rec)

	imageTag, err := in.builder.Build(ctx, manifest.ID, manifest.Version, buildDir)
	if err != nil {
		return in.fail(ctx, rec, "build", ErrBuildFailed, err)
	}
	rec.ImageTag = imageTag
	rec.UpdatedAt = in.opts.Now().UnixMilli()
	_ = in.records.Update(ctx, rec)

	keyID, err := in.secrets.Provision(ctx, manifest.ID)
	if err != nil {
		return in.rollback(ctx, rec, "secret", ErrRunFailed, err, imageTag, "")
	}
	_ = keyID

	port := portFromUpstream(manifest.Upstream)
	containerName := "tools-" + manifest.ID
	spec := ContainerSpec{
		Slug: manifest.ID, Version: manifest.Version, ImageTag: imageTag,
		ContainerName: containerName, Network: in.opts.Network, InternalPort: port,
		NetworkAliases: []string{upstreamHost(manifest.Upstream)},
		HMACKeysDir:    filepath.Join(in.hostKeysDir()),
		Env: map[string]string{
			"TOOL_SLUG":          manifest.ID,
			"TOOL_HMAC_KEYS_DIR": "/run/secrets/tool-hmac",
		},
		MemoryLimitMiB: in.opts.MemoryLimitMiB, CPULimit: in.opts.CPULimit, PidsLimit: in.opts.PidsLimit,
	}
	rec.Status = model.ToolInstallStarting
	rec.ContainerName = containerName
	rec.UpdatedAt = in.opts.Now().UnixMilli()
	_ = in.records.Update(ctx, rec)

	name, err := in.runner.Run(ctx, spec)
	if err != nil {
		return in.rollback(ctx, rec, "run", ErrRunFailed, err, imageTag, "")
	}
	rec.ContainerName = name

	if err := in.waitHealthy(ctx, name); err != nil {
		return in.rollback(ctx, rec, "health", ErrUnhealthy, err, imageTag, name)
	}

	toolID, err := in.registrar.Register(ctx, manifest, manifest.Upstream)
	if err != nil {
		return in.rollback(ctx, rec, "register", ErrRegistrationFailed, err, imageTag, name)
	}
	rec.ToolID = toolID
	rec.Status = model.ToolInstallInstalled
	rec.UpdatedAt = in.opts.Now().UnixMilli()
	if err := in.records.Update(ctx, rec); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRegistrationFailed, err)
	}
	return rec, nil
}

// waitHealthy polls the container health until it passes or the timeout fires.
//
// The deadline is measured against the wall clock rather than the injectable
// business clock: health waiting is real elapsed time, and tests should not be
// forced to simulate the passage of time. The health timeout is therefore
// wall-clock bounded, which also matches how the operator experiences it.
func (in *Installer) waitHealthy(ctx context.Context, containerName string) error {
	deadline := time.Now().Add(in.opts.HealthTimeout)
	for {
		ok, err := in.runner.Healthy(ctx, containerName)
		if err == nil && ok {
			return nil
		}
		if !time.Now().Before(deadline) {
			if err != nil {
				return fmt.Errorf("%w: %v", ErrUnhealthy, err)
			}
			return ErrUnhealthy
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(in.opts.HealthPollInterval):
		}
	}
}

// rollback tears down partially created resources and records the failure.
func (in *Installer) rollback(ctx context.Context, rec *InstallRecord, stage string, sentinel, cause error, imageTag, containerName string) (*InstallRecord, error) {
	if containerName != "" {
		_ = in.runner.Stop(ctx, containerName)
		_ = in.runner.Remove(ctx, containerName)
	}
	if imageTag != "" {
		_ = in.builder.Remove(ctx, imageTag)
	}
	_ = in.secrets.Revoke(ctx, rec.Slug)
	rec.Status = model.ToolInstallFailed
	rec.ErrorCode = stage
	rec.ErrorMessage = cause.Error()
	rec.UpdatedAt = in.opts.Now().UnixMilli()
	_ = in.records.Update(ctx, rec)
	return rec, fmt.Errorf("%w: %s: %v", sentinel, stage, cause)
}

// fail records a failure that happened before any resource existed.
func (in *Installer) fail(ctx context.Context, rec *InstallRecord, stage string, sentinel, cause error) (*InstallRecord, error) {
	rec.Status = model.ToolInstallFailed
	rec.ErrorCode = stage
	rec.ErrorMessage = cause.Error()
	rec.UpdatedAt = in.opts.Now().UnixMilli()
	_ = in.records.Update(ctx, rec)
	return rec, fmt.Errorf("%w: %s: %v", sentinel, stage, cause)
}

// Uninstall stops and removes a tool and its registration.
func (in *Installer) Uninstall(ctx context.Context, slug string) error {
	in.mu.Lock()
	defer in.mu.Unlock()
	if !IsValidSlug(slug) {
		return fmt.Errorf("%w: invalid slug", ErrInvalidRequest)
	}
	rec, err := in.records.BySlug(ctx, slug)
	if err != nil || rec == nil {
		return fmt.Errorf("%w: %s", ErrNotInstalled, slug)
	}
	rec.Status = model.ToolInstallRemoving
	rec.UpdatedAt = in.opts.Now().UnixMilli()
	_ = in.records.Update(ctx, rec)

	if rec.ContainerName != "" {
		_ = in.runner.Stop(ctx, rec.ContainerName)
		_ = in.runner.Remove(ctx, rec.ContainerName)
	}
	if rec.ImageTag != "" {
		_ = in.builder.Remove(ctx, rec.ImageTag)
	}
	_ = in.secrets.Revoke(ctx, slug)
	_ = in.registrar.Remove(ctx, slug)

	rec.Status = model.ToolInstallRemoved
	rec.UpdatedAt = in.opts.Now().UnixMilli()
	_ = in.records.Update(ctx, rec)
	return nil
}

// portFromUpstream extracts the port from an upstream URL, defaulting to 8000.
// upstreamHost returns the hostname of a manifest upstream URL, or "" when the
// URL is missing or has no host. It is used as the container network alias so
// the manifest upstream resolves on the tool network.
func upstreamHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// hostKeysDir returns the directory the Docker daemon should use as the bind
// source when mounting the HMAC key directory into a tool container. The
// installer usually runs in a container itself, so its own view of the path
// (for example /run/secrets/tool-hmac) does not exist on the host and would
// produce an empty mount. HMACKeysHostDir carries the real host path.
func (in *Installer) hostKeysDir() string {
	if in.opts.HMACKeysHostDir != "" {
		return in.opts.HMACKeysHostDir
	}
	return in.opts.HMACKeysDir
}

func portFromUpstream(raw string) int {
	u, err := url.Parse(raw)
	if err != nil || u.Port() == "" {
		return 8000
	}
	port := 0
	for _, ch := range u.Port() {
		if ch < '0' || ch > '9' {
			return 8000
		}
		port = port*10 + int(ch-'0')
	}
	if port == 0 {
		return 8000
	}
	return port
}

// Record returns the stored install record for a slug, or nil when none
// exists. The error is reserved for storage failures.
func (in *Installer) Record(ctx context.Context, slug string) (*InstallRecord, error) {
	if !IsValidSlug(slug) {
		return nil, fmt.Errorf("%w: invalid slug", ErrInvalidRequest)
	}
	return in.records.BySlug(ctx, slug)
}

// Records returns every install record, newest first.
func (in *Installer) Records(ctx context.Context) ([]InstallRecord, error) {
	return in.records.List(ctx)
}

// SetToolStatus changes the published status of an installed tool. Only the
// lifecycle-relevant statuses are accepted so the installer cannot silently
// transition a tool into an unexpected state.
func (in *Installer) SetToolStatus(ctx context.Context, slug string, status string) error {
	in.mu.Lock()
	defer in.mu.Unlock()
	if !IsValidSlug(slug) {
		return fmt.Errorf("%w: invalid slug", ErrInvalidRequest)
	}
	switch status {
	case model.ToolStatusActive, model.ToolStatusDisabled, model.ToolStatusMaintenance, model.ToolStatusDraft:
	default:
		return fmt.Errorf("%w: invalid tool status %q", ErrInvalidRequest, status)
	}
	rec, err := in.records.BySlug(ctx, slug)
	if err != nil {
		return err
	}
	if rec == nil {
		return fmt.Errorf("%w: %s", ErrNotInstalled, slug)
	}
	if err := in.registrar.SetStatus(ctx, slug, status); err != nil {
		return err
	}
	rec.UpdatedAt = in.opts.Now().UnixMilli()
	_ = in.records.Update(ctx, rec)
	return nil
}
