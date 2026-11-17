package repository

import (
	"context"
	"time"

	"gorm.io/gorm"

	"github.com/winduputra/MyCorePlat/pkg/toolauth"
)

// NonceRepository is the shared, atomic replay-protection store backed by the
// hmac_nonces table (migration 000002).
//
// Atomicity comes from the table's composite primary key plus a single
// INSERT ... ON DUPLICATE KEY UPDATE statement: the "have I seen this nonce?"
// test and the "record it" write happen in one statement, so two concurrent
// replays cannot both be admitted.
type NonceRepository struct {
	db *gorm.DB
}

// NewNonceRepository wraps db.
func NewNonceRepository(db *gorm.DB) *NonceRepository {
	return &NonceRepository{db: db}
}

var _ toolauth.NonceStore = (*NonceRepository)(nil)

// insertNonceSQL stores a nonce and replaces an already-expired row for the same
// pair. MySQL reports 0 affected rows when the existing row is still live (no
// change applied), which is exactly the replay case.
const insertNonceSQL = `
INSERT INTO hmac_nonces (key_id, nonce, expires_at, created_at)
VALUES (?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
    expires_at = IF(expires_at <= ?, VALUES(expires_at), expires_at)`

// CheckAndStore implements toolauth.NonceStore.
func (r *NonceRepository) CheckAndStore(ctx context.Context, keyID, nonce string, ttl time.Duration) error {
	if r == nil || r.db == nil {
		return toolauth.ErrNonceStoreUnavailable
	}
	if ttl <= 0 {
		ttl = toolauth.DefaultNonceTTL
	}
	now := time.Now().UTC()
	result := r.db.WithContext(ctx).Exec(insertNonceSQL, keyID, nonce, now.Add(ttl), now, now)
	if result.Error != nil {
		// The caller (and the verifier) must fail closed on any storage error.
		return toolauth.ErrNonceStoreUnavailable
	}
	if result.RowsAffected == 0 {
		return toolauth.ErrNonceReused
	}
	return nil
}

// DeleteExpired removes nonce rows whose TTL has elapsed and returns how many
// were deleted. Called periodically by the Core janitor; safe to run at any time.
func (r *NonceRepository) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	if r == nil || r.db == nil {
		return 0, toolauth.ErrNonceStoreUnavailable
	}
	result := r.db.WithContext(ctx).Exec("DELETE FROM hmac_nonces WHERE expires_at <= ?", before.UTC())
	if result.Error != nil {
		return 0, toolauth.ErrNonceStoreUnavailable
	}
	return result.RowsAffected, nil
}
