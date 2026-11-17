package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	"gorm.io/gorm"

	"github.com/winduputra/MyCorePlat/internal/model"
	"github.com/winduputra/MyCorePlat/internal/service"
)

// mysqlDuplicateEntry is MySQL/MariaDB error 1062 (ER_DUP_ENTRY). GORM's
// TranslateError is not enabled, so duplicate-key collisions are recognized by
// the driver error number rather than gorm.ErrDuplicatedKey.
const mysqlDuplicateEntry = 1062

var _ service.AccessTokenRepository = (*AccessTokenRepository)(nil)

// AccessTokenRepository provides persistence for tool access tokens. It
// satisfies service.AccessTokenRepository. Only token hashes are ever written.
type AccessTokenRepository struct {
	db *gorm.DB
}

// NewAccessTokenRepository constructs an AccessTokenRepository.
func NewAccessTokenRepository(db *gorm.DB) *AccessTokenRepository {
	return &AccessTokenRepository{db: db}
}

// Create inserts a new token row. A duplicate token hash (astronomically
// unlikely, but the column is UNIQUE) is mapped to a distinct sentinel so the
// service can report a collision rather than a generic database error.
func (r *AccessTokenRepository) Create(ctx context.Context, token *model.AccessToken) error {
	if err := r.db.WithContext(ctx).Create(token).Error; err != nil {
		var myErr *mysqldriver.MySQLError
		if errors.As(err, &myErr) && myErr.Number == mysqlDuplicateEntry {
			return service.ErrAccessTokenHashCollision
		}
		return fmt.Errorf("create access token: %w", err)
	}
	return nil
}

// FindByHash returns the token with the given hash, or
// service.ErrAccessTokenNotFound. It does NOT filter on expiry or revocation —
// the service enforces those so callers cannot distinguish failure reasons by
// timing or wording.
func (r *AccessTokenRepository) FindByHash(ctx context.Context, hash string) (*model.AccessToken, error) {
	var token model.AccessToken
	err := r.db.WithContext(ctx).
		Where("token_hash = ?", hash).
		Take(&token).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, service.ErrAccessTokenNotFound
		}
		return nil, fmt.Errorf("find access token by hash: %w", err)
	}
	return &token, nil
}

// ListByTool returns every token for a tool (live or not) so the admin UI can
// display revoked/expired state. Newest first.
func (r *AccessTokenRepository) ListByTool(ctx context.Context, toolID uint64) ([]model.AccessToken, error) {
	var tokens []model.AccessToken
	err := r.db.WithContext(ctx).
		Where("tool_id = ?", toolID).
		Order("created_at DESC, id DESC").
		Find(&tokens).Error
	if err != nil {
		return nil, fmt.Errorf("list access tokens: %w", err)
	}
	return tokens, nil
}

// Revoke sets revoked_at on a token, but only when the token belongs to the
// given tool. A cross-tool attempt reports service.ErrAccessTokenNotFound and
// mutates nothing.
func (r *AccessTokenRepository) Revoke(ctx context.Context, toolID, id uint64, at time.Time) error {
	res := r.db.WithContext(ctx).
		Model(&model.AccessToken{}).
		Where("id = ? AND tool_id = ? AND revoked_at IS NULL", id, toolID).
		Update("revoked_at", at.UTC())
	if res.Error != nil {
		return fmt.Errorf("revoke access token: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		// Either the token does not exist, belongs to another tool, or is
		// already revoked. Report not-found; the caller must not learn which.
		return service.ErrAccessTokenNotFound
	}
	return nil
}

// TouchLastUsed stamps last_used_at. It is best-effort and never fails a valid
// request; the service ignores the returned error.
func (r *AccessTokenRepository) TouchLastUsed(ctx context.Context, id uint64, at time.Time) error {
	res := r.db.WithContext(ctx).
		Model(&model.AccessToken{}).
		Where("id = ?", id).
		Update("last_used_at", at.UTC())
	if res.Error != nil {
		return fmt.Errorf("touch access token last_used_at: %w", res.Error)
	}
	return nil
}
