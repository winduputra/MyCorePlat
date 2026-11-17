package service

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/winduputra/MyCorePlat/internal/model"
)

// toolSlugPattern matches lowercase alphanumerics joined by single hyphens.
var toolSlugPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// ToolInput is the server-validated set of fields used to create or update a
// tool. It deliberately excludes immutable/derived columns (id, timestamps,
// deleted_at). Status and AccessType are validated against the allowed enums,
// so client input is never trusted blindly.
type ToolInput struct {
	Slug               string
	Name               string
	Description        string
	Category           string
	Version            string
	Runtime            string
	AccessType         string
	UpstreamURL        string
	HealthcheckPath    string
	Status             string
	MaintenanceMessage string
	ManifestJSON       string
	DisplayOrder       int
}

// ToolService implements tool registry business rules on top of a
// ToolRepository. Validation and slug uniqueness live here so handlers stay
// thin and the rules are enforced regardless of caller. The upstream allowlist
// is supplied at construction from server-side configuration only.
type ToolService struct {
	repo  ToolRepository
	allow UpstreamAllowlist
}

// NewToolService constructs a ToolService. The allowlist gates which upstream
// hostnames are permitted and must come from configuration, never from client
// input or a manifest.
func NewToolService(repo ToolRepository, allow UpstreamAllowlist) *ToolService {
	return &ToolService{repo: repo, allow: allow}
}

// List returns all non-deleted tools.
func (s *ToolService) List(ctx context.Context) ([]model.Tool, error) {
	return s.repo.List(ctx)
}

// Get returns a single tool by id or ErrToolNotFound.
func (s *ToolService) Get(ctx context.Context, id uint64) (*model.Tool, error) {
	return s.repo.GetByID(ctx, id)
}

// GetBySlug returns a single tool by slug or ErrToolNotFound.
func (s *ToolService) GetBySlug(ctx context.Context, slug string) (*model.Tool, error) {
	return s.repo.GetBySlug(ctx, slug)
}

// Create validates input, enforces unique slug, and persists a new tool.
func (s *ToolService) Create(ctx context.Context, in ToolInput) (*model.Tool, error) {
	in.normalize()
	if err := in.validate(s.allow); err != nil {
		return nil, err
	}

	// Enforce slug uniqueness (a DB unique index also guards this; the explicit
	// check yields a clean error instead of leaking a driver constraint error).
	if _, err := s.repo.GetBySlug(ctx, in.Slug); err == nil {
		return nil, fmt.Errorf("%w: %q", ErrDuplicateSlug, in.Slug)
	} else if err != ErrToolNotFound {
		return nil, err
	}

	tool := in.toModel()
	if err := s.repo.Create(ctx, tool); err != nil {
		return nil, err
	}
	return tool, nil
}

// Update validates input and persists changes to an existing tool.
func (s *ToolService) Update(ctx context.Context, id uint64, in ToolInput) (*model.Tool, error) {
	in.normalize()
	if err := in.validate(s.allow); err != nil {
		return nil, err
	}

	current, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// If the slug is changing, ensure the target slug is free.
	if current.Slug != in.Slug {
		if other, err := s.repo.GetBySlug(ctx, in.Slug); err == nil && other.ID != id {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateSlug, in.Slug)
		} else if err != nil && err != ErrToolNotFound {
			return nil, err
		}
	}

	updated := in.toModel()
	updated.ID = id
	updated.CreatedAt = current.CreatedAt
	if err := s.repo.Update(ctx, updated); err != nil {
		return nil, err
	}
	return updated, nil
}

// Delete soft-deletes a tool.
func (s *ToolService) Delete(ctx context.Context, id uint64) error {
	return s.repo.SoftDelete(ctx, id)
}

// ImportManifest parses and validates a manifest, then creates a tool from its
// seed fields. DB-managed status defaults to draft and access_type comes from
// the manifest's *request* only; the manifest can never force an active/expired
// state or other security setting (see docs/tool-integration.md).
func (s *ToolService) ImportManifest(ctx context.Context, data []byte) (*model.Tool, error) {
	m, err := ParseManifest(data, s.allow)
	if err != nil {
		return nil, err
	}

	in := ToolInput{
		Slug:            m.ID,
		Name:            m.Name,
		Description:     m.Description,
		Category:        m.Category,
		Version:         m.Version,
		Runtime:         m.Runtime,
		AccessType:      m.Access,
		UpstreamURL:     m.Upstream,
		HealthcheckPath: m.Healthcheck,
		Status:          model.ToolStatusDraft, // DB default; manifest cannot set active
		ManifestJSON:    string(data),
		DisplayOrder:    m.DisplayOrder,
	}
	// Validate that access from the manifest is a known value even before
	// persisting.
	if !model.IsValidToolAccess(in.AccessType) {
		return nil, fmt.Errorf("%w: access %q", ErrInvalidManifest, in.AccessType)
	}
	return s.Create(ctx, in)
}

// normalize trims user-provided strings and fills safe defaults.
func (in *ToolInput) normalize() {
	in.Slug = strings.TrimSpace(strings.ToLower(in.Slug))
	in.Name = strings.TrimSpace(in.Name)
	in.Description = strings.TrimSpace(in.Description)
	in.Category = strings.TrimSpace(in.Category)
	in.Version = strings.TrimSpace(in.Version)
	in.Runtime = strings.TrimSpace(strings.ToLower(in.Runtime))
	in.AccessType = strings.TrimSpace(strings.ToLower(in.AccessType))
	in.UpstreamURL = strings.TrimSpace(in.UpstreamURL)
	in.HealthcheckPath = strings.TrimSpace(in.HealthcheckPath)
	in.Status = strings.TrimSpace(strings.ToLower(in.Status))
	in.MaintenanceMessage = strings.TrimSpace(in.MaintenanceMessage)

	if in.Status == "" {
		in.Status = model.ToolStatusDraft
	}
	if in.AccessType == "" {
		in.AccessType = model.ToolAccessPublic
	}
	if in.HealthcheckPath == "" {
		in.HealthcheckPath = "/health"
	}
}

// validate enforces field rules. Sensitive/enumerated fields are validated
// server-side; invalid values are rejected rather than coerced. The upstream
// host must be on the configuration-supplied allowlist.
func (in *ToolInput) validate(allow UpstreamAllowlist) error {
	if err := validateSlug(in.Slug); err != nil {
		return err
	}
	if in.Name == "" || len(in.Name) > 128 {
		return fmt.Errorf("name must be 1-128 characters")
	}
	if len(in.Description) > 512 {
		return fmt.Errorf("description must be at most 512 characters")
	}
	if len(in.Category) > 64 {
		return fmt.Errorf("category must be at most 64 characters")
	}
	if len(in.Version) > 32 {
		return fmt.Errorf("version must be at most 32 characters")
	}
	if len(in.Runtime) > 32 {
		return fmt.Errorf("runtime must be at most 32 characters")
	}
	if !model.IsValidToolStatus(in.Status) {
		return fmt.Errorf("invalid status %q", in.Status)
	}
	if !model.IsValidToolAccess(in.AccessType) {
		return fmt.Errorf("invalid access type %q", in.AccessType)
	}
	if err := ValidateUpstream(in.UpstreamURL, allow); err != nil {
		return err
	}
	if !strings.HasPrefix(in.HealthcheckPath, "/") || len(in.HealthcheckPath) > 128 {
		return fmt.Errorf("healthcheck path must start with / and be at most 128 characters")
	}
	if len(in.MaintenanceMessage) > 512 {
		return fmt.Errorf("maintenance message must be at most 512 characters")
	}
	if in.DisplayOrder < 0 {
		return fmt.Errorf("display order must be >= 0")
	}
	return nil
}

// toModel maps validated input to a model.Tool. Nullable optional fields are
// stored as pointers so empty strings become NULL.
func (in *ToolInput) toModel() *model.Tool {
	return &model.Tool{
		Slug:               in.Slug,
		Name:               in.Name,
		Description:        nilIfEmpty(in.Description),
		Category:           nilIfEmpty(in.Category),
		Version:            nilIfEmpty(in.Version),
		Runtime:            nilIfEmpty(in.Runtime),
		AccessType:         in.AccessType,
		UpstreamURL:        in.UpstreamURL,
		HealthcheckPath:    in.HealthcheckPath,
		Status:             in.Status,
		MaintenanceMessage: nilIfEmpty(in.MaintenanceMessage),
		ManifestJSON:       nilIfEmpty(in.ManifestJSON),
		DisplayOrder:       in.DisplayOrder,
	}
}

// validateSlug enforces the tools.slug UUID-friendly pattern: lowercase
// alphanumerics joined by single hyphens, at most 64 chars.
func validateSlug(slug string) error {
	if slug == "" {
		return fmt.Errorf("slug is required")
	}
	if len(slug) > 64 {
		return fmt.Errorf("slug must be at most 64 characters")
	}
	if !toolSlugPattern.MatchString(slug) {
		return fmt.Errorf("slug must contain only lowercase letters, digits and single hyphens")
	}
	return nil
}

// nilIfEmpty returns nil for empty strings so GORM stores SQL NULL.
func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	v := s
	return &v
}
