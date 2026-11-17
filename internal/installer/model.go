package installer

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Sentinel errors returned by the installer. They are deliberately coarse so
// they can be shown to the operator without leaking internal detail.
var (
	// ErrInvalidRequest is returned when the caller supplied an unusable input.
	ErrInvalidRequest = fmt.Errorf("invalid install request")
	// ErrPackageInvalid is returned when a package fails validation.
	ErrPackageInvalid = fmt.Errorf("tool package is invalid")
	// ErrBuildFailed is returned when the container image cannot be built.
	ErrBuildFailed = fmt.Errorf("tool image build failed")
	// ErrRunFailed is returned when the tool container cannot be started.
	ErrRunFailed = fmt.Errorf("tool container did not start")
	// ErrRegistrationFailed is returned when the tool cannot be registered.
	ErrRegistrationFailed = fmt.Errorf("tool registration failed")
	// ErrUnhealthy is returned when the tool does not become healthy in time.
	ErrUnhealthy = fmt.Errorf("tool did not become healthy")
	// ErrConflict is returned when the slug is already installed.
	ErrConflict = fmt.Errorf("tool is already installed")
	// ErrNotInstalled is returned when the slug has no installation record.
	ErrNotInstalled = fmt.Errorf("tool is not installed")
	// ErrLifecycleBusy is returned when an install/update/remove is in progress.
	ErrLifecycleBusy = fmt.Errorf("another lifecycle operation is in progress")
)

// slugPattern is the canonical tool slug shape. It matches the Core manifest
// and gateway patterns exactly so one tool has exactly one URL.
var slugPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// IsValidSlug reports whether slug is an acceptable tool identifier.
func IsValidSlug(slug string) bool {
	return slug != "" && len(slug) <= 63 && slugPattern.MatchString(slug)
}

// Package is a validated, inspected tool package ready to be installed.
type Package struct {
	// Slug is the tool identifier taken from the manifest.
	Slug string
	// Manifest is the parsed manifest of the package.
	Manifest Manifest
	// SHA256 is the hex SHA-256 of the uploaded archive.
	SHA256 string
	// Bytes is the raw archive. It is kept so the image build context can be
	// materialised exactly once.
	Bytes []byte
}

// Manifest is the subset of manifest.json the installer needs. The full
// validation happens in pkg/tooldist; this mirrors the fields required to
// build, run and register the tool.
type Manifest struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	Description   string `json:"description"`
	Category      string `json:"category,omitempty"`
	Access        string `json:"access"`
	Runtime       string `json:"runtime"`
	Upstream      string `json:"upstream"`
	Healthcheck   string `json:"healthcheck"`
	DisplayOrder  int    `json:"displayOrder,omitempty"`
	Icon          string `json:"icon,omitempty"`
	SchemaVersion string `json:"schemaVersion,omitempty"`
}

// InstallRequest is the input of a synchronous install call.
type InstallRequest struct {
	// PackageBytes is the raw uploaded ZIP archive.
	PackageBytes []byte
	// AdminID is the administrator that triggered the install.
	AdminID uint64
	// Now is the clock used to stamp records. Zero means time.Now.
	Now time.Time
}

// Healthy reports whether the manifest declares a health path usable for
// start-up verification. A manifest without a health path cannot be verified
// and is treated as invalid by the installer.
func (m Manifest) Healthy() bool {
	return strings.HasPrefix(m.Healthcheck, "/")
}
