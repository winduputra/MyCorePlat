package tooldist

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// parseManifest decodes and validates the manifest.json inside a package.
//
// The authoritative validation (allowlist checks on upstream, status/access
// ownership) happens in Core when the tool is registered. Here we only need the
// identity fields to be well-formed so the installer knows what it is about to
// build and where to send it.
func parseManifest(data []byte) (*Manifest, error) {
	if len(bytesTrim(data)) == 0 {
		return nil, fmt.Errorf("%w: %s is empty", ErrInvalidPackage, ManifestName)
	}

	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%w: %s is not valid JSON for the package schema", ErrInvalidPackage, ManifestName)
	}

	m.ID = strings.TrimSpace(m.ID)
	m.Name = strings.TrimSpace(m.Name)
	m.Version = strings.TrimSpace(m.Version)
	m.Runtime = strings.ToLower(strings.TrimSpace(m.Runtime))
	m.Access = strings.ToLower(strings.TrimSpace(m.Access))
	m.Upstream = strings.TrimSpace(m.Upstream)
	m.Healthcheck = strings.TrimSpace(m.Healthcheck)

	if err := validateManifestFields(&m); err != nil {
		return nil, err
	}
	return &m, nil
}

var (
	manifestVersionPattern = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-.]+)?(?:\+[0-9A-Za-z-.]+)?$`)
	manifestRuntimes       = map[string]bool{"python": true, "php": true, "node": true, "go": true}
)

func validateManifestFields(m *Manifest) error {
	if m.ID == "" || len(m.ID) > 63 || !slugPattern.MatchString(m.ID) {
		return fmt.Errorf("%w: manifest id must match ^[a-z0-9]+(-[a-z0-9]+)*$ and be at most 63 characters", ErrInvalidPackage)
	}
	if m.Name == "" || len(m.Name) > 128 {
		return fmt.Errorf("%w: manifest name is required (max 128 characters)", ErrInvalidPackage)
	}
	if !manifestVersionPattern.MatchString(m.Version) {
		return fmt.Errorf("%w: manifest version must be semver (for example 1.0.0)", ErrInvalidPackage)
	}
	if m.Description == "" || len(m.Description) > 512 {
		return fmt.Errorf("%w: manifest description is required (max 512 characters)", ErrInvalidPackage)
	}
	if m.Category != "" && len(m.Category) > 64 {
		return fmt.Errorf("%w: manifest category is too long", ErrInvalidPackage)
	}
	if m.Access != "public" && m.Access != "token" {
		return fmt.Errorf("%w: manifest access must be \"public\" or \"token\"", ErrInvalidPackage)
	}
	if !manifestRuntimes[m.Runtime] {
		return fmt.Errorf("%w: manifest runtime must be one of python, php, node, go", ErrInvalidPackage)
	}
	if m.Upstream == "" || len(m.Upstream) > 255 {
		return fmt.Errorf("%w: manifest upstream is required", ErrInvalidPackage)
	}
	if !strings.HasPrefix(m.Healthcheck, "/") || len(m.Healthcheck) > 128 {
		return fmt.Errorf("%w: manifest healthcheck must start with /", ErrInvalidPackage)
	}
	if m.DisplayOrder < 0 {
		return fmt.Errorf("%w: manifest displayOrder must not be negative", ErrInvalidPackage)
	}
	if len(m.Icon) > 64 {
		return fmt.Errorf("%w: manifest icon is too long", ErrInvalidPackage)
	}
	if len(m.SchemaVersion) > 16 {
		return fmt.Errorf("%w: manifest schemaVersion is too long", ErrInvalidPackage)
	}
	return nil
}

func bytesTrim(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}
