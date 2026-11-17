package repository_test

import (
	"context"
	"os"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/winduputra/MyCorePlat/internal/model"
	"github.com/winduputra/MyCorePlat/internal/repository"
	"github.com/winduputra/MyCorePlat/internal/service"
)

// openDevDB connects to the dev MariaDB when DEV_DB_DSN is set, otherwise skips.
// Tests that mutate data clean up after themselves so the shared dev database
// stays usable between runs.
func openDevDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("DEV_DB_DSN")
	if dsn == "" {
		t.Skip("DEV_DB_DSN not set; skipping MariaDB integration test")
	}
	db, err := repository.Open(context.Background(), dsn, repository.DefaultPoolSettings())
	if err != nil {
		t.Fatalf("open dev db: %v", err)
	}
	t.Cleanup(func() { repository.Close(db) })
	return db
}

func uniqueUsername(t *testing.T) string {
	t.Helper()
	return "test-admin-" + time.Now().UTC().Format("20060102150405.000000000")
}

// TestAdminRepositoryLifecycle exercises FindByUsername + UpdateLastLogin on
// real MariaDB, cleaning up the inserted admin.
func TestAdminRepositoryLifecycle(t *testing.T) {
	db := openDevDB(t)
	ctx := context.Background()
	repo := repository.NewAdminRepository(db)

	username := uniqueUsername(t)
	admin := &model.Admin{
		Username:     username,
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0$hashhashhash",
		Role:         "superadmin",
		IsActive:     true,
	}
	if err := db.Create(admin).Error; err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	t.Cleanup(func() {
		db.Where("username = ?", username).Delete(&model.Admin{})
	})

	got, err := repo.FindByUsername(ctx, username)
	if err != nil {
		t.Fatalf("FindByUsername: %v", err)
	}
	if got.ID != admin.ID {
		t.Fatalf("got admin id %d, want %d", got.ID, admin.ID)
	}

	if _, err := repo.FindByUsername(ctx, "definitely-no-such-admin"); err != service.ErrAdminNotFound {
		t.Fatalf("missing admin error = %v, want ErrAdminNotFound", err)
	}

	if err := repo.UpdateLastLogin(ctx, admin.ID); err != nil {
		t.Fatalf("UpdateLastLogin: %v", err)
	}
	reloaded, err := repo.FindByUsername(ctx, username)
	if err != nil {
		t.Fatalf("reload admin: %v", err)
	}
	if reloaded.LastLoginAt == nil {
		t.Fatal("last_login_at was not set")
	}
}

// TestSessionRepositoryLifecycle proves the real repository stores and finds a
// session by hash, and that revoke sets revoked_at — end to end on MariaDB.
func TestSessionRepositoryLifecycle(t *testing.T) {
	db := openDevDB(t)
	ctx := context.Background()
	adminRepo := repository.NewAdminRepository(db)
	sessionRepo := repository.NewSessionRepository(db)

	username := uniqueUsername(t)
	admin := &model.Admin{
		Username:     username,
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0$hashhashhash",
		Role:         "superadmin",
		IsActive:     true,
	}
	if err := db.Create(admin).Error; err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	t.Cleanup(func() {
		// admin_sessions.admin_id has ON DELETE CASCADE, so removing the admin
		// clears its sessions too.
		db.Where("username = ?", username).Delete(&model.Admin{})
	})

	svc := service.NewSessionService(sessionRepo, time.Hour)
	plaintext, session, err := svc.Create(ctx, admin.ID, service.SessionMeta{IPAddress: "127.0.0.1", UserAgent: "go-test"})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// The persisted row must store the hash, never the plaintext.
	stored, err := sessionRepo.FindByTokenHash(ctx, service.HashToken(plaintext))
	if err != nil {
		t.Fatalf("find session by hash: %v", err)
	}
	if stored.SessionTokenHash == plaintext {
		t.Fatal("repository stored the plaintext token")
	}
	if stored.ID != session.ID {
		t.Fatalf("stored session id %d, want %d", stored.ID, session.ID)
	}

	// Service-level validate succeeds, then fails after revoke.
	if _, err := svc.Validate(ctx, plaintext); err != nil {
		t.Fatalf("validate before revoke: %v", err)
	}
	if err := svc.Revoke(ctx, session.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := svc.Validate(ctx, plaintext); err != service.ErrSessionRevoked {
		t.Fatalf("validate after revoke = %v, want ErrSessionRevoked", err)
	}

	_ = adminRepo // keep the admin repo construction asserted as compiles
}
