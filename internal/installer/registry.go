package installer

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/winduputra/MyCorePlat/internal/model"
	"github.com/winduputra/MyCorePlat/internal/repository"
	"github.com/winduputra/MyCorePlat/internal/service"
)

// ServiceToolRegistrar registers installed tools through the Core tool
// registry service, so the gateway can route them by slug. It deliberately
// reuses service.ToolService rather than writing to the database directly:
// slug validation, upstream SSRF validation and the enforced default status
// stay in one place.
type ServiceToolRegistrar struct {
	tools *service.ToolService
	repo  *repository.ToolRepository
	now   func() time.Time
}

var _ ToolRegistrar = (*ServiceToolRegistrar)(nil)

// NewServiceToolRegistrar builds a registrar backed by the tool registry.
func NewServiceToolRegistrar(tools *service.ToolService, repo *repository.ToolRepository) *ServiceToolRegistrar {
	return &ServiceToolRegistrar{tools: tools, repo: repo, now: time.Now}
}

// Register creates or updates the tool row for an installed package. An
// existing row is reused (update) so a re-install after a failed attempt does
// not fail on the unique slug constraint.
func (r *ServiceToolRegistrar) Register(ctx context.Context, manifest Manifest, upstreamURL string) (uint64, error) {
	if r == nil || r.tools == nil {
		return 0, fmt.Errorf("%w: tool registry is not configured", ErrRegistrationFailed)
	}

	healthcheck := manifest.Healthcheck
	if healthcheck == "" {
		healthcheck = "/health"
	}

	input := service.ToolInput{
		Slug:            manifest.ID,
		Name:            manifest.Name,
		Description:     manifest.Description,
		Category:        manifest.Category,
		Version:         manifest.Version,
		Runtime:         manifest.Runtime,
		AccessType:      manifest.Access,
		UpstreamURL:     upstreamURL,
		HealthcheckPath: healthcheck,
		DisplayOrder:    manifest.DisplayOrder,
		// Status is intentionally left empty: ToolInput.normalize defaults it
		// to draft so a freshly installed tool is never auto-published.
	}

	existing, err := r.tools.GetBySlug(ctx, manifest.ID)
	switch {
	case errors.Is(err, service.ErrToolNotFound):
		created, createErr := r.tools.Create(ctx, input)
		if createErr != nil {
			// A previous installation of the same slug may still hold the
			// unique slug in a soft-deleted row. Revive that row instead of
			// failing the whole installation.
			if revivedID, reviveErr := r.repo.ReviveBySlug(ctx, manifest.ID); reviveErr == nil {
				updated, updateErr := r.tools.Update(ctx, revivedID, input)
				if updateErr != nil {
					return 0, fmt.Errorf("%w: %v", ErrRegistrationFailed, updateErr)
				}
				return updated.ID, nil
			}
			return 0, fmt.Errorf("%w: %v", ErrRegistrationFailed, createErr)
		}
		return created.ID, nil
	case err != nil:
		return 0, fmt.Errorf("%w: %v", ErrRegistrationFailed, err)
	}

	updated, updateErr := r.tools.Update(ctx, existing.ID, input)
	if updateErr != nil {
		return 0, fmt.Errorf("%w: %v", ErrRegistrationFailed, updateErr)
	}
	return updated.ID, nil
}

// SetStatus changes the tool status (draft, active, maintenance, disabled).
func (r *ServiceToolRegistrar) SetStatus(ctx context.Context, slug string, status string) error {
	if r == nil || r.tools == nil {
		return fmt.Errorf("%w: tool registry is not configured", ErrRegistrationFailed)
	}
	tool, err := r.tools.GetBySlug(ctx, slug)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRegistrationFailed, err)
	}

	updated := service.ToolInput{
		Slug:            tool.Slug,
		Name:            tool.Name,
		Description:     derefString(tool.Description),
		Category:        derefString(tool.Category),
		Version:         derefString(tool.Version),
		Runtime:         derefString(tool.Runtime),
		AccessType:      tool.AccessType,
		UpstreamURL:     tool.UpstreamURL,
		HealthcheckPath: tool.HealthcheckPath,
		Status:          status,
		DisplayOrder:    tool.DisplayOrder,
	}
	if tool.MaintenanceMessage != nil {
		updated.MaintenanceMessage = *tool.MaintenanceMessage
	}
	if tool.ManifestJSON != nil {
		updated.ManifestJSON = *tool.ManifestJSON
	}

	if _, err := r.tools.Update(ctx, tool.ID, updated); err != nil {
		return fmt.Errorf("%w: %v", ErrRegistrationFailed, err)
	}
	return nil
}

// Remove soft-deletes the tool row so the gateway stops routing to it while
// audit records that reference the tool keep working.
func (r *ServiceToolRegistrar) Remove(ctx context.Context, slug string) error {
	if r == nil || r.tools == nil {
		return fmt.Errorf("%w: tool registry is not configured", ErrRegistrationFailed)
	}
	tool, err := r.tools.GetBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, service.ErrToolNotFound) {
			return nil
		}
		return fmt.Errorf("%w: %v", ErrRegistrationFailed, err)
	}
	if err := r.tools.Delete(ctx, tool.ID); err != nil {
		if errors.Is(err, service.ErrToolNotFound) {
			return nil
		}
		return fmt.Errorf("%w: %v", ErrRegistrationFailed, err)
	}
	return nil
}

// GormInstallRecordStore persists installer job state in MariaDB.
type GormInstallRecordStore struct {
	db *gorm.DB
}

var _ InstallRecordStore = (*GormInstallRecordStore)(nil)

// NewGormInstallRecordStore builds a record store over the given connection.
func NewGormInstallRecordStore(db *gorm.DB) *GormInstallRecordStore {
	return &GormInstallRecordStore{db: db}
}

// Create inserts a new installer record and assigns its id back to rec.
func (s *GormInstallRecordStore) Create(ctx context.Context, rec *InstallRecord) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("%w: install record store is not configured", ErrInvalidRequest)
	}
	if rec == nil {
		return fmt.Errorf("%w: install record is required", ErrInvalidRequest)
	}

	now := time.Now().UTC()
	row := installRowFromRecord(*rec)
	row.CreatedAt = now
	row.UpdatedAt = now

	if err := s.db.WithContext(ctx).Create(&row).Error; err != nil {
		return fmt.Errorf("create install record: %w", err)
	}
	rec.ID = row.ID
	rec.CreatedAt = now.UnixMilli()
	rec.UpdatedAt = now.UnixMilli()
	return nil
}

// Update persists the mutable job fields of a record.
func (s *GormInstallRecordStore) Update(ctx context.Context, rec *InstallRecord) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("%w: install record store is not configured", ErrInvalidRequest)
	}
	if rec == nil || rec.ID == 0 {
		return fmt.Errorf("%w: install record id is required", ErrInvalidRequest)
	}

	updatedAt := time.Now().UTC()
	updates := map[string]any{
		"tool_id":        nullableUint64(rec.ToolID),
		"status":         rec.Status,
		"version":        nullableString(rec.Version),
		"image_tag":      nullableString(rec.ImageTag),
		"container_name": nullableString(rec.ContainerName),
		"package_sha256": nullableString(rec.PackageSHA256),
		"error_code":     nullableString(rec.ErrorCode),
		"error_message":  nullableString(rec.ErrorMessage),
		"updated_at":     updatedAt,
	}

	result := s.db.WithContext(ctx).
		Model(&model.ToolInstall{}).
		Where("id = ?", rec.ID).
		Updates(updates)
	if result.Error != nil {
		return fmt.Errorf("update install record: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%w: install record %d", ErrNotInstalled, rec.ID)
	}
	rec.UpdatedAt = updatedAt.UnixMilli()
	return nil
}

// BySlug returns the most recent record for a slug.
func (s *GormInstallRecordStore) BySlug(ctx context.Context, slug string) (*InstallRecord, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("%w: install record store is not configured", ErrInvalidRequest)
	}
	var row model.ToolInstall
	err := s.db.WithContext(ctx).
		Where("slug = ?", slug).
		Order("id DESC").
		Take(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find install record: %w", err)
	}
	rec := recordFromInstallRow(row)
	return &rec, nil
}

// List returns all installer records newest first.
func (s *GormInstallRecordStore) List(ctx context.Context) ([]InstallRecord, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("%w: install record store is not configured", ErrInvalidRequest)
	}
	var rows []model.ToolInstall
	if err := s.db.WithContext(ctx).Order("id DESC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list install records: %w", err)
	}
	records := make([]InstallRecord, 0, len(rows))
	for _, row := range rows {
		records = append(records, recordFromInstallRow(row))
	}
	return records, nil
}

// Delete removes a record permanently.
func (s *GormInstallRecordStore) Delete(ctx context.Context, slug string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("%w: install record store is not configured", ErrInvalidRequest)
	}
	result := s.db.WithContext(ctx).
		Where("slug = ?", slug).
		Delete(&model.ToolInstall{})
	if result.Error != nil {
		return fmt.Errorf("delete install record: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%w: %s", ErrNotInstalled, slug)
	}
	return nil
}

func installRowFromRecord(rec InstallRecord) model.ToolInstall {
	row := model.ToolInstall{
		ID:                 rec.ID,
		Slug:               rec.Slug,
		Status:             rec.Status,
		InstalledByAdminID: nullableUint64(rec.InstalledByAdmin),
		Version:            nullableString(rec.Version),
		ImageTag:           nullableString(rec.ImageTag),
		ContainerName:      nullableString(rec.ContainerName),
		PackageSHA256:      nullableString(rec.PackageSHA256),
		ErrorCode:          nullableString(rec.ErrorCode),
		ErrorMessage:       nullableString(rec.ErrorMessage),
	}
	if rec.ToolID != 0 {
		toolID := rec.ToolID
		row.ToolID = &toolID
	}
	return row
}

func recordFromInstallRow(row model.ToolInstall) InstallRecord {
	rec := InstallRecord{
		ID:            row.ID,
		Slug:          row.Slug,
		Status:        row.Status,
		Version:       derefString(row.Version),
		ImageTag:      derefString(row.ImageTag),
		ContainerName: derefString(row.ContainerName),
		PackageSHA256: derefString(row.PackageSHA256),
		ErrorCode:     derefString(row.ErrorCode),
		ErrorMessage:  derefString(row.ErrorMessage),
		CreatedAt:     row.CreatedAt.UTC().UnixMilli(),
		UpdatedAt:     row.UpdatedAt.UTC().UnixMilli(),
	}
	if row.ToolID != nil {
		rec.ToolID = *row.ToolID
	}
	if row.InstalledByAdminID != nil {
		rec.InstalledByAdmin = *row.InstalledByAdminID
	}
	return rec
}

func nullableString(value string) *string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

func nullableUint64(value uint64) *uint64 {
	if value == 0 {
		return nil
	}
	return &value
}

func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
