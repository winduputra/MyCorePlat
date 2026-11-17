package model

import "time"

// AdminSession is a server-side admin session (tables: admin_sessions).
//
// Only a hash of the session token is stored (SessionTokenHash); the plaintext
// token lives only in the client's HttpOnly cookie. CSRFToken holds the
// per-session CSRF secret used to validate state-changing requests.
type AdminSession struct {
	ID               uint64     `gorm:"column:id;primaryKey"`
	AdminID          uint64     `gorm:"column:admin_id"`
	SessionTokenHash string     `gorm:"column:session_token_hash"`
	CSRFToken        string     `gorm:"column:csrf_token"`
	IPAddress        *string    `gorm:"column:ip_address"`
	UserAgent        *string    `gorm:"column:user_agent"`
	ExpiresAt        time.Time  `gorm:"column:expires_at"`
	CreatedAt        time.Time  `gorm:"column:created_at"`
	RevokedAt        *time.Time `gorm:"column:revoked_at"`
}

// TableName pins the model to the migrated table name.
func (AdminSession) TableName() string { return "admin_sessions" }
