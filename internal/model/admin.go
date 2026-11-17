// Package model holds GORM models and domain entities for the Core application.
// Models map 1:1 to tables defined by the golang-migrate migrations; they are
// never used to auto-create schema (no AutoMigrate).
package model

import "time"

// Admin is an administrator account (tables: admins).
//
// Only the Argon2id password hash is ever stored in PasswordHash; plaintext
// passwords are never persisted.
type Admin struct {
	ID           uint64     `gorm:"column:id;primaryKey"`
	Username     string     `gorm:"column:username"`
	PasswordHash string     `gorm:"column:password_hash"`
	Role         string     `gorm:"column:role"`
	IsActive     bool       `gorm:"column:is_active"`
	LastLoginAt  *time.Time `gorm:"column:last_login_at"`
	CreatedAt    time.Time  `gorm:"column:created_at"`
	UpdatedAt    time.Time  `gorm:"column:updated_at"`
}

// TableName pins the model to the migrated table name.
func (Admin) TableName() string { return "admins" }
