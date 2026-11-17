package model

import "time"

// AccessToken maps the access_tokens table. A token grants access to exactly one
// tool and never carries an identity of its own: recipient_label is descriptive
// documentation, not authentication.
//
// Only the hash of a token is ever persisted. The plaintext exists solely in the
// response that created it.
type AccessToken struct {
	ID               uint64     `gorm:"column:id;primaryKey"`
	ToolID           uint64     `gorm:"column:tool_id"`
	TokenHash        string     `gorm:"column:token_hash"`
	TokenPrefix      string     `gorm:"column:token_prefix"`
	RecipientLabel   *string    `gorm:"column:recipient_label"`
	ExpiresAt        time.Time  `gorm:"column:expires_at"`
	RevokedAt        *time.Time `gorm:"column:revoked_at"`
	CreatedByAdminID uint64     `gorm:"column:created_by_admin_id"`
	LastUsedAt       *time.Time `gorm:"column:last_used_at"`
	CreatedAt        time.Time  `gorm:"column:created_at"`
}

// TableName pins the model to the migrated table name.
func (AccessToken) TableName() string { return "access_tokens" }

// IsLive reports whether the token is currently usable: not revoked and not
// expired. Expiry is mandatory, so ExpiresAt is never the zero value for a row
// that was created by the token service.
func (t *AccessToken) IsLive(now time.Time) bool {
	if t == nil {
		return false
	}
	if t.RevokedAt != nil {
		return false
	}
	return t.ExpiresAt.After(now)
}

// IsRevoked reports whether the token has been revoked.
func (t *AccessToken) IsRevoked() bool {
	return t != nil && t.RevokedAt != nil
}
