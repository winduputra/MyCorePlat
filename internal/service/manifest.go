package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrInvalidManifest is returned when a tool manifest fails parsing or
// validation. Callers map it to a 4xx response.
var ErrInvalidManifest = errors.New("invalid manifest")

// Manifest is the parsed and validated representation of a tool manifest.
//
// SECURITY: this struct intentionally contains NO status or access-control
// field. The manifest is a *request*; the enforced status and access_type are
// owned by the database (see docs/tool-integration.md and §3.3 of
// docs/database-design.md). Any unknown field — including "status", "enabled",
// or other control fields — is rejected during parsing so a manifest can never
// override DB-managed security settings.
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

// Manifest field constraints mirrored from docs/tool-integration.md (§2.5 JSON
// Schema). Kept in Go so validation does not depend on a JSON-schema library.
var (
	// Equivalent to the JSON Schema id pattern
	// ^[a-z0-9](?:[a-z0-9]|-(?=[a-z0-9])){0,62}$, rewritten for Go's RE2
	// engine which has no lookahead: one or more alphanumeric runs joined by
	// single hyphens. This rejects leading/trailing hyphens, double hyphens and
	// underscores while accepting names like "image-compressor". Overall length
	// (<=63) is checked separately.
	manifestIDPattern      = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	manifestVersionPattern = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-.]+)?(?:\+[0-9A-Za-z-.]+)?$`)
)

var manifestRuntimes = map[string]bool{
	"python": true, "php": true, "node": true, "go": true,
}

// ParseManifest decodes and validates a tool manifest against the server-side
// upstream allowlist. Unknown fields are rejected; required fields, enums,
// patterns and the upstream SSRF policy are enforced. It never executes or
// downloads anything described by the manifest. The allowlist comes from
// configuration only — never from the manifest or any client input.
func ParseManifest(data []byte, allow UpstreamAllowlist) (*Manifest, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("%w: empty document", ErrInvalidManifest)
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%w: decode: %v", ErrInvalidManifest, err)
	}
	// Reject trailing content after the first JSON value.
	if dec.More() {
		return nil, fmt.Errorf("%w: unexpected trailing data", ErrInvalidManifest)
	}

	if err := m.validate(allow); err != nil {
		return nil, err
	}
	return &m, nil
}

// validate applies field-level rules. It assumes required fields' presence is
// guaranteed by the zero-value checks below (all required fields are non-empty
// except DisplayOrder, which is optional with a valid default of 0).
func (m *Manifest) validate(allow UpstreamAllowlist) error {
	if len(m.ID) == 0 || len(m.ID) > 63 || !manifestIDPattern.MatchString(m.ID) {
		return fmt.Errorf("%w: invalid id %q", ErrInvalidManifest, m.ID)
	}
	if m.Name == "" || len(m.Name) > 128 {
		return fmt.Errorf("%w: name must be 1-128 chars", ErrInvalidManifest)
	}
	if !manifestVersionPattern.MatchString(m.Version) {
		return fmt.Errorf("%w: invalid version %q", ErrInvalidManifest, m.Version)
	}
	if m.Description == "" || len(m.Description) > 512 {
		return fmt.Errorf("%w: description must be 1-512 chars", ErrInvalidManifest)
	}
	if len(m.Category) > 64 {
		return fmt.Errorf("%w: category too long", ErrInvalidManifest)
	}
	if m.Access != "public" && m.Access != "token" {
		return fmt.Errorf("%w: access must be public or token", ErrInvalidManifest)
	}
	if !manifestRuntimes[m.Runtime] {
		return fmt.Errorf("%w: runtime %q not allowed", ErrInvalidManifest, m.Runtime)
	}
	if m.Upstream == "" {
		return fmt.Errorf("%w: upstream is required", ErrInvalidManifest)
	}
	if err := ValidateUpstream(m.Upstream, allow); err != nil {
		// Surface as an invalid manifest while preserving the sentinel.
		return fmt.Errorf("%w: %v", ErrInvalidManifest, err)
	}
	if !strings.HasPrefix(m.Healthcheck, "/") || len(m.Healthcheck) > 128 {
		return fmt.Errorf("%w: healthcheck must start with /", ErrInvalidManifest)
	}
	if m.DisplayOrder < 0 {
		return fmt.Errorf("%w: displayOrder must be >= 0", ErrInvalidManifest)
	}
	if len(m.Icon) > 64 {
		return fmt.Errorf("%w: icon too long", ErrInvalidManifest)
	}
	if len(m.SchemaVersion) > 16 {
		return fmt.Errorf("%w: schemaVersion too long", ErrInvalidManifest)
	}
	return nil
}
