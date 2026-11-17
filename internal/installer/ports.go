package installer

import "context"

// ImageBuilder builds and manages container images for tool packages.
//
// A production implementation talks to the Docker Engine API. It MUST NOT be
// exposed to Core: only the installer process holds these credentials.
type ImageBuilder interface {
	// Build builds a container image for the extracted build context and
	// returns the immutable image tag that was produced.
	Build(ctx context.Context, slug, version, buildContextDir string) (imageTag string, err error)
	// Remove removes the image tag. Errors are treated as best-effort by the
	// caller during rollback.
	Remove(ctx context.Context, imageTag string) error
}

// ContainerRunner manages the runtime container for a tool.
type ContainerRunner interface {
	// Run starts a container for the tool and returns its container name.
	Run(ctx context.Context, spec ContainerSpec) (containerName string, err error)
	// Stop stops a running container (best effort).
	Stop(ctx context.Context, containerName string) error
	// Remove deletes a container (best effort).
	Remove(ctx context.Context, containerName string) error
	// Healthy reports whether the container's healthcheck currently passes.
	Healthy(ctx context.Context, containerName string) (bool, error)
}

// ContainerSpec describes how a tool container must be started. The installer
// fills this from the manifest plus its own policy; the runner never decides
// policy on its own.
type ContainerSpec struct {
	Slug          string
	Version       string
	ImageTag      string
	ContainerName string
	// Network is the isolated tool network the container joins.
	Network string
	// NetworkAliases are extra DNS names on that network. The installer adds
	// the manifest upstream hostname so `http://<host>:<port>` in the manifest
	// resolves to this container even though the container name carries a
	// uniqueness suffix.
	NetworkAliases []string
	// InternalPort is the container port the tool listens on.
	InternalPort int
	// HMACKeysDir is the host directory holding the per-tool HMAC key file,
	// mounted read-only into the container.
	HMACKeysDir string
	// Env are additional environment variables (never secrets).
	Env map[string]string
	// MemoryLimitMiB and CPUQuota size the container.
	MemoryLimitMiB int
	CPULimit       float64
	PidsLimit      int
}

// SecretProvisioner writes the per-tool HMAC key file that Core uses to sign
// requests and the tool uses to verify them.
//
// The plaintext secret is generated here, stored once in the keystore
// directory, and never logged or persisted anywhere else.
type SecretProvisioner interface {
	// Provision creates (or rotates) the key file for the slug and returns the
	// key id that was made active.
	Provision(ctx context.Context, slug string) (keyID string, err error)
	// Revoke removes the key file for the slug (best effort during uninstall).
	Revoke(ctx context.Context, slug string) error
}

// ToolRegistrar registers and updates a tool in the Core database so the
// gateway can route to it. The installer calls this only after the container is
// proven healthy.
type ToolRegistrar interface {
	// Register creates or updates the tool record for the manifest. It returns
	// the tool id.
	Register(ctx context.Context, m Manifest, upstreamURL string) (toolID uint64, err error)
	// SetStatus changes a tool's status (active/draft/maintenance/disabled).
	SetStatus(ctx context.Context, slug, status string) error
	// Remove soft-deletes the tool record.
	Remove(ctx context.Context, slug string) error
}

// InstallRecordStore persists the lifecycle records shown to the operator.
type InstallRecordStore interface {
	// Create inserts a new install record and returns its id.
	Create(ctx context.Context, rec *InstallRecord) error
	// Update writes the current state of an existing record.
	Update(ctx context.Context, rec *InstallRecord) error
	// BySlug returns the latest record for a slug.
	BySlug(ctx context.Context, slug string) (*InstallRecord, error)
	// List returns all records, newest first.
	List(ctx context.Context) ([]InstallRecord, error)
	// Delete removes the record for a slug.
	Delete(ctx context.Context, slug string) error
}

// InstallRecord is the persistent state of one tool installation.
type InstallRecord struct {
	ID               uint64
	ToolID           uint64
	Slug             string
	Status           string
	Version          string
	ImageTag         string
	ContainerName    string
	PackageSHA256    string
	ErrorCode        string
	ErrorMessage     string
	InstalledByAdmin uint64
	CreatedAt        int64
	UpdatedAt        int64
}
