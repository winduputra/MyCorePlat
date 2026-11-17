package repository

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/winduputra/MyCorePlat/internal/model"
	"github.com/winduputra/MyCorePlat/internal/service"
)

// ToolRepository persists tool registry records.
//
// The tools model uses *time.Time for DeletedAt (matching the migration), not
// gorm.DeletedAt, so GORM does NOT apply a soft-delete scope automatically.
// Every read and mutation below therefore filters on `deleted_at IS NULL`
// explicitly, so deleted tools are unreachable through the registry as required
// by docs/database-design.md §3.3.
type ToolRepository struct {
	db *gorm.DB
}

// NewToolRepository constructs a ToolRepository.
func NewToolRepository(db *gorm.DB) *ToolRepository {
	return &ToolRepository{db: db}
}

// List returns all non-deleted tools ordered for stable display.
func (r *ToolRepository) List(ctx context.Context) ([]model.Tool, error) {
	var tools []model.Tool
	err := r.db.WithContext(ctx).
		Where("deleted_at IS NULL").
		Order("display_order ASC, name ASC").
		Find(&tools).Error
	if err != nil {
		return nil, fmt.Errorf("list tools: %w", err)
	}
	return tools, nil
}

// GetByID returns a single non-deleted tool or service.ErrToolNotFound.
func (r *ToolRepository) GetByID(ctx context.Context, id uint64) (*model.Tool, error) {
	var tool model.Tool
	err := r.db.WithContext(ctx).Where("deleted_at IS NULL").First(&tool, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, service.ErrToolNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get tool: %w", err)
	}
	return &tool, nil
}

// GetBySlug returns a single non-deleted tool by slug or service.ErrToolNotFound.
func (r *ToolRepository) GetBySlug(ctx context.Context, slug string) (*model.Tool, error) {
	var tool model.Tool
	err := r.db.WithContext(ctx).
		Where("deleted_at IS NULL").
		Where("slug = ?", slug).
		First(&tool).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, service.ErrToolNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get tool by slug: %w", err)
	}
	return &tool, nil
}

// Create inserts a new tool, assigning the generated id back to tool.
func (r *ToolRepository) Create(ctx context.Context, tool *model.Tool) error {
	if err := r.db.WithContext(ctx).Create(tool).Error; err != nil {
		return fmt.Errorf("create tool: %w", err)
	}
	return nil
}

// Update persists changes to an existing tool. updated_at is refreshed
// server-side.
func (r *ToolRepository) Update(ctx context.Context, tool *model.Tool) error {
	res := r.db.WithContext(ctx).
		Model(&model.Tool{}).
		Where("id = ?", tool.ID).
		Where("deleted_at IS NULL").
		Select("slug", "name", "description", "category", "version", "runtime",
			"access_type", "upstream_url", "healthcheck_path", "status",
			"maintenance_message", "manifest_json", "display_order").
		Updates(tool)
	if res.Error != nil {
		return fmt.Errorf("update tool: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return service.ErrToolNotFound
	}
	return nil
}

// SoftDelete marks a tool deleted by setting deleted_at.
func (r *ToolRepository) SoftDelete(ctx context.Context, id uint64) error {
	res := r.db.WithContext(ctx).
		Model(&model.Tool{}).
		Where("id = ?", id).
		Where("deleted_at IS NULL").
		Update("deleted_at", gorm.Expr("UTC_TIMESTAMP(3)"))
	if res.Error != nil {
		return fmt.Errorf("delete tool: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return service.ErrToolNotFound
	}
	return nil
}
