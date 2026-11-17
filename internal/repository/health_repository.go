package repository

import (
	"context"

	"gorm.io/gorm"

	"github.com/winduputra/MyCorePlat/internal/model"
	"github.com/winduputra/MyCorePlat/internal/service"
)

// ToolHealthRepository is the GORM-backed store for tool_health_checks.
type ToolHealthRepository struct {
	db *gorm.DB
}

// NewToolHealthRepository builds the repository.
func NewToolHealthRepository(db *gorm.DB) *ToolHealthRepository {
	return &ToolHealthRepository{db: db}
}

var _ service.ToolHealthRepository = (*ToolHealthRepository)(nil)

// Insert appends one probe result. checked_at is always supplied by the caller
// because the migrated table has no default.
func (r *ToolHealthRepository) Insert(ctx context.Context, check *model.ToolHealthCheck) error {
	if r.db == nil {
		return gorm.ErrInvalidDB
	}
	return r.db.WithContext(ctx).Create(check).Error
}

// LatestByTool returns the most recent check per tool id in one query.
func (r *ToolHealthRepository) LatestByTool(ctx context.Context, toolIDs []uint64) (map[uint64]*model.ToolHealthCheck, error) {
	out := make(map[uint64]*model.ToolHealthCheck)
	if r.db == nil {
		return out, gorm.ErrInvalidDB
	}
	if len(toolIDs) == 0 {
		return out, nil
	}

	rows := make([]model.ToolHealthCheck, 0)
	err := r.db.WithContext(ctx).
		Model(&model.ToolHealthCheck{}).
		Where("tool_id IN ?", toolIDs).
		Order("tool_id ASC, checked_at DESC, id DESC").
		Find(&rows).Error
	if err != nil {
		return nil, err
	}
	for i := range rows {
		row := rows[i]
		if _, seen := out[row.ToolID]; !seen {
			out[row.ToolID] = &row
		}
	}
	return out, nil
}

// ListByTool returns recent history for one tool, newest first.
func (r *ToolHealthRepository) ListByTool(ctx context.Context, toolID uint64, limit int) ([]model.ToolHealthCheck, error) {
	if r.db == nil {
		return nil, gorm.ErrInvalidDB
	}
	if limit <= 0 {
		limit = 50
	}
	rows := make([]model.ToolHealthCheck, 0)
	err := r.db.WithContext(ctx).
		Model(&model.ToolHealthCheck{}).
		Where("tool_id = ?", toolID).
		Order("checked_at DESC, id DESC").
		Limit(limit).
		Find(&rows).Error
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// PreviousStatus returns the status of the most recent recorded check for a
// tool, or "" when the tool has never been checked.
func (r *ToolHealthRepository) PreviousStatus(ctx context.Context, toolID uint64) (string, error) {
	if r.db == nil {
		return "", gorm.ErrInvalidDB
	}
	var row model.ToolHealthCheck
	err := r.db.WithContext(ctx).
		Model(&model.ToolHealthCheck{}).
		Where("tool_id = ?", toolID).
		Order("checked_at DESC, id DESC").
		Limit(1).
		Take(&row).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return "", nil
		}
		return "", err
	}
	return row.Status, nil
}
