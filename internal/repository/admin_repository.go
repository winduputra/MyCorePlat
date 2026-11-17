package repository

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/winduputra/MyCorePlat/internal/model"
	"github.com/winduputra/MyCorePlat/internal/service"
)

// AdminRepository provides persistence for administrator accounts.
type AdminRepository struct {
	db *gorm.DB
}

// NewAdminRepository constructs an AdminRepository over the given DB handle.
func NewAdminRepository(db *gorm.DB) *AdminRepository {
	return &AdminRepository{db: db}
}

// FindByUsername returns the admin with the given username, or
// service.ErrAdminNotFound. The lookup is a parameterized equality match (no
// string concatenation).
func (r *AdminRepository) FindByUsername(ctx context.Context, username string) (*model.Admin, error) {
	var admin model.Admin
	err := r.db.WithContext(ctx).
		Where("username = ?", username).
		Take(&admin).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, service.ErrAdminNotFound
		}
		return nil, fmt.Errorf("find admin by username: %w", err)
	}
	return &admin, nil
}

// UpdateLastLogin records the successful login time for an admin.
func (r *AdminRepository) UpdateLastLogin(ctx context.Context, adminID uint64) error {
	res := r.db.WithContext(ctx).
		Model(&model.Admin{}).
		Where("id = ?", adminID).
		Update("last_login_at", gorm.Expr("UTC_TIMESTAMP(3)"))
	if res.Error != nil {
		return fmt.Errorf("update last login: %w", res.Error)
	}
	return nil
}
