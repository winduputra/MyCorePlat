package repository

import (
	"context"

	"gorm.io/gorm"

	"github.com/winduputra/MyCorePlat/internal/model"
	"github.com/winduputra/MyCorePlat/internal/service"
)

// ActivityLogRepository is the GORM-backed implementation of the audit log
// store. The table is append-only: there is no update or delete here.
type ActivityLogRepository struct {
	db *gorm.DB
}

// NewActivityLogRepository builds the repository.
func NewActivityLogRepository(db *gorm.DB) *ActivityLogRepository {
	return &ActivityLogRepository{db: db}
}

var _ service.ActivityLogRepository = (*ActivityLogRepository)(nil)

// Insert appends one activity row. created_at is always supplied by the caller
// because the migrated table has no default.
func (r *ActivityLogRepository) Insert(ctx context.Context, entry *model.ActivityLog) error {
	if r.db == nil {
		return gorm.ErrInvalidDB
	}
	return r.db.WithContext(ctx).Create(entry).Error
}

// List returns a page of rows newest-first together with the total count that
// matches the same filter (used for pagination).
func (r *ActivityLogRepository) List(ctx context.Context, filter service.ActivityFilter) ([]model.ActivityLog, int64, error) {
	if r.db == nil {
		return nil, 0, gorm.ErrInvalidDB
	}

	query := r.db.WithContext(ctx).Model(&model.ActivityLog{})
	if filter.Action != "" {
		query = query.Where("action = ?", filter.Action)
	}
	if filter.EntityType != "" {
		query = query.Where("entity_type = ?", filter.EntityType)
	}
	if filter.ToolID != nil {
		query = query.Where("tool_id = ?", *filter.ToolID)
	}
	if filter.From != nil {
		query = query.Where("created_at >= ?", filter.From.UTC())
	}
	if filter.To != nil {
		query = query.Where("created_at <= ?", filter.To.UTC())
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	rows := make([]model.ActivityLog, 0)
	err := query.
		Order("created_at DESC, id DESC").
		Limit(filter.Limit).
		Offset(filter.Offset).
		Find(&rows).Error
	if err != nil {
		return nil, 0, err
	}
	return rows, total, nil
}
