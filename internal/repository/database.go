// Package repository contains data-access code (via GORM), one repository per
// aggregate. This file provides the shared database connection used by all
// repositories.
package repository

import (
	"context"
	"fmt"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// PoolSettings controls the underlying database/sql connection pool.
type PoolSettings struct {
	// MaxOpenConns caps the number of open connections to the database.
	MaxOpenConns int
	// MaxIdleConns caps the number of idle connections kept in the pool.
	MaxIdleConns int
	// ConnMaxLifetime bounds how long a connection may be reused.
	ConnMaxLifetime time.Duration
	// ConnMaxIdleTime bounds how long an idle connection is kept before closing.
	ConnMaxIdleTime time.Duration
}

// DefaultPoolSettings returns conservative pool settings suited to the Core
// gateway's moderate concurrency.
func DefaultPoolSettings() PoolSettings {
	return PoolSettings{
		MaxOpenConns:    25,
		MaxIdleConns:    10,
		ConnMaxLifetime: time.Hour,
		ConnMaxIdleTime: 10 * time.Minute,
	}
}

// Open establishes a GORM connection to MariaDB, applies pool settings, and
// verifies connectivity with a bounded PingContext.
//
// It deliberately does NOT run AutoMigrate: schema changes are managed solely
// by golang-migrate migrations. The DSN is never logged.
func Open(ctx context.Context, dsn string, pool PoolSettings) (*gorm.DB, error) {
	if dsn == "" {
		return nil, fmt.Errorf("open database: empty DSN")
	}

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		// Silence GORM's default logger; the application logs through its own
		// logger and must never emit connection strings or queries with values.
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		// GORM's error may include the DSN; replace it with a generic message.
		return nil, fmt.Errorf("open database: connection failed")
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("open database: obtain sql.DB handle: %w", err)
	}

	sqlDB.SetMaxOpenConns(pool.MaxOpenConns)
	sqlDB.SetMaxIdleConns(pool.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(pool.ConnMaxLifetime)
	sqlDB.SetConnMaxIdleTime(pool.ConnMaxIdleTime)

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := sqlDB.PingContext(pingCtx); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("open database: ping failed: %w", err)
	}

	return db, nil
}

// Ping verifies connectivity using a bounded context. It is used by health
// checks to report database reachability without panicking on failure.
func Ping(ctx context.Context, db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("ping database: nil handle")
	}
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("ping database: obtain sql.DB handle: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return sqlDB.PingContext(pingCtx)
}

// Close releases the underlying connection pool.
func Close(db *gorm.DB) error {
	if db == nil {
		return nil
	}
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("close database: obtain sql.DB handle: %w", err)
	}
	return sqlDB.Close()
}
