package repository

import (
	"context"

	"gorm.io/gorm"

	"github.com/winduputra/MyCorePlat/internal/model"
	"github.com/winduputra/MyCorePlat/internal/service"
)

// HealthTargetRepository supplies the tools the health poller may probe.
//
// It is a separate repository (rather than a method on ToolRepository) so the
// poller's read path is narrow and cannot accidentally mutate tool state:
// health monitoring never changes a tool's status.
type HealthTargetRepository struct {
	db *gorm.DB
}

// NewHealthTargetRepository builds the repository.
func NewHealthTargetRepository(db *gorm.DB) *HealthTargetRepository {
	return &HealthTargetRepository{db: db}
}

var _ service.HealthTargetRepository = (*HealthTargetRepository)(nil)

// ListActiveSlugs returns the slugs of active, non-deleted tools.
func (r *HealthTargetRepository) ListActiveSlugs(ctx context.Context) ([]string, error) {
	if r.db == nil {
		return nil, gorm.ErrInvalidDB
	}
	slugs := make([]string, 0)
	err := r.db.WithContext(ctx).
		Model(&model.Tool{}).
		Where("status = ? AND deleted_at IS NULL", model.ToolStatusActive).
		Order("display_order ASC, id ASC").
		Pluck("slug", &slugs).Error
	if err != nil {
		return nil, err
	}
	return slugs, nil
}

// GetForHealth returns one active tool by slug, or service.ErrToolNotFound.
func (r *HealthTargetRepository) GetForHealth(ctx context.Context, slug string) (*model.Tool, error) {
	if r.db == nil {
		return nil, gorm.ErrInvalidDB
	}
	var tool model.Tool
	err := r.db.WithContext(ctx).
		Model(&model.Tool{}).
		Where("slug = ? AND deleted_at IS NULL", slug).
		Take(&tool).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, service.ErrToolNotFound
		}
		return nil, err
	}
	return &tool, nil
}
