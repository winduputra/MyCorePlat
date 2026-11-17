package installer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// DockerImageBuilder implements ImageBuilder on top of the Docker Engine API.
type DockerImageBuilder struct {
	client *dockerClient
}

// NewDockerImageBuilder connects to the Docker daemon. It fails fast when the
// daemon is unreachable so the installer refuses to start half-configured.
func NewDockerImageBuilder(ctx context.Context) (*DockerImageBuilder, error) {
	c, err := newDockerClient()
	if err != nil {
		return nil, err
	}
	if err := c.ping(ctx); err != nil {
		return nil, fmt.Errorf("docker daemon unreachable: %w", err)
	}
	return &DockerImageBuilder{client: c}, nil
}

// Build builds an image tagged tools-bpbj/<slug>:<version>.
func (b *DockerImageBuilder) Build(ctx context.Context, slug, version, buildContextDir string) (string, error) {
	tag := fmt.Sprintf("tools-bpbj/%s:%s", slug, version)
	if err := b.client.buildImage(ctx, tag, buildContextDir, "Dockerfile"); err != nil {
		return "", err
	}
	return tag, nil
}

// Remove removes the image tag.
func (b *DockerImageBuilder) Remove(ctx context.Context, imageTag string) error {
	return b.client.removeImage(ctx, imageTag)
}

// DockerContainerRunner implements ContainerRunner on top of the Docker Engine
// API, applying the installer's security policy to every container.
type DockerContainerRunner struct {
	client *dockerClient
}

// NewDockerContainerRunner connects to the Docker daemon.
func NewDockerContainerRunner(ctx context.Context) (*DockerContainerRunner, error) {
	c, err := newDockerClient()
	if err != nil {
		return nil, err
	}
	if err := c.ping(ctx); err != nil {
		return nil, fmt.Errorf("docker daemon unreachable: %w", err)
	}
	return &DockerContainerRunner{client: c}, nil
}

// Run creates and starts a container for the tool.
func (r *DockerContainerRunner) Run(ctx context.Context, spec ContainerSpec) (string, error) {
	name, err := r.client.createContainer(ctx, spec, spec.HMACKeysDir)
	if err != nil {
		return "", err
	}
	if err := r.client.startContainer(ctx, name); err != nil {
		// Best effort cleanup of the container that failed to start.
		_ = r.client.removeContainer(ctx, name)
		return "", err
	}
	return name, nil
}

// Stop stops a running container.
func (r *DockerContainerRunner) Stop(ctx context.Context, containerName string) error {
	return r.client.stopContainer(ctx, containerName)
}

// Remove deletes a container.
func (r *DockerContainerRunner) Remove(ctx context.Context, containerName string) error {
	return r.client.removeContainer(ctx, containerName)
}

// Healthy reports whether the container's healthcheck currently passes. A
// container without a healthcheck is treated as healthy once it is running.
func (r *DockerContainerRunner) Healthy(ctx context.Context, containerName string) (bool, error) {
	status, err := r.client.containerHealth(ctx, containerName)
	if err != nil {
		return false, err
	}
	switch status {
	case "healthy", "none":
		return true, nil
	default:
		return false, nil
	}
}

// FileSecretProvisioner writes per-tool HMAC key files into a directory shared
// with Core's keystore and mounted read-only into tool containers.
type FileSecretProvisioner struct {
	dir string
	now func() time.Time
}

// NewFileSecretProvisioner builds a provisioner writing <dir>/<slug>.json.
func NewFileSecretProvisioner(dir string) *FileSecretProvisioner {
	return &FileSecretProvisioner{dir: dir, now: time.Now}
}

// Provision writes a fresh key file for the slug with one active key.
func (p *FileSecretProvisioner) Provision(_ context.Context, slug string) (string, error) {
	if !IsValidSlug(slug) {
		return "", fmt.Errorf("%w: invalid slug", ErrInvalidRequest)
	}
	// The directory must be traversable and the key file readable by the Core
	// process, which runs under a DIFFERENT uid (distroless nonroot 65532) than
	// the installer (10002). A 0600 file would therefore be unreadable by Core
	// and every signed request would fail. Confidentiality is enforced by the
	// mounted volume being shared only between Core and the installer, never
	// with tools or the wider host.
	if err := os.MkdirAll(p.dir, 0o755); err != nil {
		return "", err
	}
	secret, err := randomSecret()
	if err != nil {
		return "", err
	}
	keyID := "k-" + p.now().UTC().Format("20060102") + "-" + shortID()
	content := keyFile{
		ToolSlug: slug,
		Keys: []keyEntry{{
			KeyID:  keyID,
			Secret: encodeBase64Std(secret),
			Status: "active",
		}},
	}
	data, err := jsonMarshalIndent(content)
	if err != nil {
		return "", err
	}
	path := filepath.Join(p.dir, slug+".json")
	tmp := path + ".tmp"
	// 0644 so the Core process (different uid) can read the key. The directory
	// is only mounted into Core and the installer, which is the trust boundary.
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	return keyID, nil
}

// Revoke removes the key file for the slug.
func (p *FileSecretProvisioner) Revoke(_ context.Context, slug string) error {
	if !IsValidSlug(slug) {
		return fmt.Errorf("%w: invalid slug", ErrInvalidRequest)
	}
	path := filepath.Join(p.dir, slug+".json")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// keyFile mirrors Core's pkg/toolauth key file format exactly.
type keyFile struct {
	ToolSlug string     `json:"toolSlug"`
	Keys     []keyEntry `json:"keys"`
}

type keyEntry struct {
	KeyID    string `json:"keyId"`
	Secret   string `json:"secret"`
	Status   string `json:"status"`
	NotAfter string `json:"notAfter,omitempty"`
}
