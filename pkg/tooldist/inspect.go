package tooldist

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
)

// Package validation limits. These bound the damage a hostile upload can do
// before any file touches disk or any container is built.
const (
	// MaxPackageBytes caps the compressed ZIP size. Enforced by the caller
	// while the upload is still streaming; re-checked here as a guard.
	MaxPackageBytes int64 = 64 << 20 // 64 MiB

	// MaxUncompressedBytes caps the total expanded size. A zip bomb that
	// expands beyond this is rejected before extraction.
	MaxUncompressedBytes int64 = 256 << 20 // 256 MiB

	// MaxEntries caps the number of files. Prevents millions of tiny files.
	MaxEntries = 2048

	// MaxPathLength caps a single entry path. Long paths are a smell and a
	// denial-of-service vector on some filesystems.
	MaxPathLength = 200

	// ManifestName is the required manifest file at the package root.
	ManifestName = "manifest.json"

	// DockerfileName is the required build recipe at the package root.
	DockerfileName = "Dockerfile"
)

// ErrInvalidPackage is the sentinel every validation failure wraps. The
// installer maps it to a generic admin-facing message (the specific reason is
// recorded in the install row, never echoed verbatim to a public surface).
var ErrInvalidPackage = fmt.Errorf("invalid tool package")

// slugPattern mirrors the registry slug rule so the manifest id can never
// disagree with the slug the installer will register.
var slugPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// InspectedFile describes one entry that survived validation.
type InspectedFile struct {
	Name             string
	UncompressedSize int64
}

// Inspection is the result of validating a ZIP package.
type Inspection struct {
	Manifest      Manifest
	Files         []InspectedFile
	TotalBytes    int64
	PackageSHA256 string
}

// Manifest is the subset of manifest.json the installer needs before the Core
// API is asked to register the tool. It intentionally mirrors the fields the
// Core manifest parser accepts; anything outside this set is ignored here and
// re-validated authoritatively by Core on registration.
type Manifest struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	Description   string `json:"description"`
	Category      string `json:"category"`
	Access        string `json:"access"`
	Runtime       string `json:"runtime"`
	Upstream      string `json:"upstream"`
	Healthcheck   string `json:"healthcheck"`
	DisplayOrder  int    `json:"displayOrder"`
	Icon          string `json:"icon"`
	SchemaVersion string `json:"schemaVersion"`
}

// Inspect validates a tool ZIP package and extracts its manifest.
//
// It never writes to disk. Every rejection wraps ErrInvalidPackage so callers
// can present a single safe message. The package hash is computed over the
// exact uploaded bytes so the install record can be tied to what was received.
func Inspect(packageBytes []byte) (*Inspection, error) {
	if len(packageBytes) == 0 {
		return nil, fmt.Errorf("%w: empty upload", ErrInvalidPackage)
	}
	if int64(len(packageBytes)) > MaxPackageBytes {
		return nil, fmt.Errorf("%w: package exceeds %d bytes", ErrInvalidPackage, MaxPackageBytes)
	}

	sum := sha256.Sum256(packageBytes)
	pkgHash := hex.EncodeToString(sum[:])

	reader, err := zip.NewReader(bytes.NewReader(packageBytes), int64(len(packageBytes)))
	if err != nil {
		return nil, fmt.Errorf("%w: not a readable zip archive", ErrInvalidPackage)
	}

	if len(reader.File) > MaxEntries {
		return nil, fmt.Errorf("%w: too many entries (%d)", ErrInvalidPackage, len(reader.File))
	}

	insp := &Inspection{PackageSHA256: pkgHash}
	var manifestBytes []byte
	haveDockerfile := false
	var total int64

	for _, f := range reader.File {
		name := f.Name

		if err := validateEntryPath(name); err != nil {
			return nil, err
		}

		// Directory entries carry no payload; they are allowed but not counted.
		if strings.HasSuffix(name, "/") {
			continue
		}

		size := int64(f.UncompressedSize64)
		if size < 0 {
			return nil, fmt.Errorf("%w: negative entry size for %q", ErrInvalidPackage, name)
		}
		total += size
		if total > MaxUncompressedBytes {
			return nil, fmt.Errorf("%w: expanded size exceeds %d bytes", ErrInvalidPackage, MaxUncompressedBytes)
		}

		insp.Files = append(insp.Files, InspectedFile{Name: name, UncompressedSize: size})

		switch name {
		case ManifestName:
			data, err := readZipFile(f)
			if err != nil {
				return nil, fmt.Errorf("%w: cannot read %s", ErrInvalidPackage, ManifestName)
			}
			manifestBytes = data
		case DockerfileName:
			haveDockerfile = true
		}
	}

	if manifestBytes == nil {
		return nil, fmt.Errorf("%w: missing %s at package root", ErrInvalidPackage, ManifestName)
	}
	if !haveDockerfile {
		return nil, fmt.Errorf("%w: missing %s at package root", ErrInvalidPackage, DockerfileName)
	}

	manifest, err := parseManifest(manifestBytes)
	if err != nil {
		return nil, err
	}
	insp.Manifest = *manifest
	insp.TotalBytes = total

	return insp, nil
}

// validateEntryPath rejects absolute paths, parent traversal (zip-slip) and
// over-long names. The rule is deliberately strict: a package may only contain
// forward-slash relative paths with no "." or ".." segments.
func validateEntryPath(name string) error {
	if name == "" {
		return fmt.Errorf("%w: empty entry name", ErrInvalidPackage)
	}
	if len(name) > MaxPathLength {
		return fmt.Errorf("%w: entry path too long", ErrInvalidPackage)
	}
	if strings.ContainsRune(name, '\\') {
		return fmt.Errorf("%w: backslash in entry path", ErrInvalidPackage)
	}
	if strings.HasPrefix(name, "/") {
		return fmt.Errorf("%w: absolute entry path", ErrInvalidPackage)
	}
	// Reject Windows drive letters such as "C:evil".
	if len(name) >= 2 && name[1] == ':' {
		return fmt.Errorf("%w: drive-letter entry path", ErrInvalidPackage)
	}

	trimmed := strings.TrimSuffix(name, "/")
	for _, seg := range strings.Split(trimmed, "/") {
		switch seg {
		case "", ".", "..":
			return fmt.Errorf("%w: unsafe path segment in entry", ErrInvalidPackage)
		}
	}

	// path.Clean must not change the path; if it does, the raw name was unsafe.
	if path.Clean(trimmed) != trimmed {
		return fmt.Errorf("%w: entry path is not clean", ErrInvalidPackage)
	}
	return nil
}

// readZipFile reads a single entry with a hard ceiling so a lying header
// (small declared size, huge real size) cannot exhaust memory.
func readZipFile(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	limit := int64(f.UncompressedSize64) + 1
	data, err := io.ReadAll(io.LimitReader(rc, limit))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > int64(f.UncompressedSize64) {
		return nil, fmt.Errorf("%w: entry larger than declared", ErrInvalidPackage)
	}
	return data, nil
}
