package repository

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/winduputra/MyCorePlat/internal/model"
	"github.com/winduputra/MyCorePlat/internal/service"
)

// SessionRepository provides persistence for admin sessions. It satisfies
// service.SessionRepository.
type SessionRepository struct {
	db *gorm.DB
}

// NewSessionRepository constructs a SessionRepository over the given DB handle.
func NewSessionRepository(db *gorm.DB) *SessionRepository {
	return &SessionRepository{db: db}
}

// Create inserts a new session row. Only the token hash is stored.
func (r *SessionRepository) Create(ctx context.Context, session *model.AdminSession) error {
	if err := r.db.WithContext(ctx).Create(session).Error; err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

// FindByTokenHash returns the session with the given token hash, or
// service.ErrSessionNotFound. It does NOT apply expiry/revocation filtering —
// the service enforces those so tests can distinguish the failure reasons.
func (r *SessionRepository) FindByTokenHash(ctx context.Context, tokenHash string) (*model.AdminSession, error) {
	var session model.AdminSession
	err := r.db.WithContext(ctx).
		Where("session_token_hash = ?", tokenHash).
		Take(&session).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, service.ErrSessionNotFound
		}
		return nil, fmt.Errorf("find session by token hash: %w", err)
	}
	return &session, nil
}

// Revoke sets revoked_at on a session. Revoking an already-revoked session is a
// no-op success.
func (r *SessionRepository) Revoke(ctx context.Context, id uint64) error {
	res := r.db.WithContext(ctx).
		Model(&model.AdminSession{}).
		Where("id = ? AND revoked_at IS NULL", id).
		Update("revoked_at", gorm.Expr("UTC_TIMESTAMP(3)"))
	if res.Error != nil {
		return fmt.Errorf("revoke session: %w", res.Error)
	}
	return nil
}
