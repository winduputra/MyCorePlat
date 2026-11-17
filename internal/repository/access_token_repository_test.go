package repository_test

import (
	"context"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/winduputra/MyCorePlat/internal/model"
	"github.com/winduputra/MyCorePlat/internal/repository"
	"github.com/winduputra/MyCorePlat/internal/service"
)

// seedTokenFixture inserts an admin and a tool for token FK constraints and
// registers cleanup for both. It returns the two IDs.
func seedTokenFixture(t *testing.T, db *gorm.DB) (adminID, toolID uint64) {
	t.Helper()

	stamp := time.Now().UTC().Format("20060102150405.000000000")

	username := "tokadm-" + stamp
	admin := &model.Admin{
		Username:     username,
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2g",
		Role:         "superadmin",
		IsActive:     true,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
	if err := db.Create(admin).Error; err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	t.Cleanup(func() {
		db.Unscoped().Where("username = ?", username).Delete(&model.Admin{})
	})

	slug := "toktool-" + stamp
	tool := &model.Tool{
		Slug:            slug,
		Name:            "Token Fixture Tool",
		AccessType:      model.ToolAccessToken,
		UpstreamURL:     "http://token-fixture:8000",
		HealthcheckPath: "/health",
		Status:          model.ToolStatusActive,
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	}
	if err := db.Create(tool).Error; err != nil {
		t.Fatalf("seed tool: %v", err)
	}
	t.Cleanup(func() {
		// access_tokens.tool_id is ON DELETE RESTRICT, so remove the tokens this
		// fixture's tool may still reference before deleting the tool itself.
		db.Unscoped().Where("tool_id = ?", tool.ID).Delete(&model.AccessToken{})
		db.Unscoped().Where("slug = ?", slug).Delete(&model.Tool{})
	})

	return admin.ID, tool.ID
}

func TestAccessTokenRepositoryLifecycle(t *testing.T) {
	db := openDevDB(t)
	ctx := context.Background()
	adminID, toolID := seedTokenFixture(t, db)
	repo := repository.NewAccessTokenRepository(db)

	now := time.Now().UTC()
	token := &model.AccessToken{
		ToolID:           toolID,
		TokenHash:        service.HashToken("tbpbj_example_secretvalue" + now.Format("150405.000000000")),
		TokenPrefix:      "prefix01",
		ExpiresAt:        now.Add(24 * time.Hour),
		CreatedByAdminID: adminID,
		CreatedAt:        now,
	}
	if err := repo.Create(ctx, token); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if token.ID == 0 {
		t.Fatal("Create did not assign an id")
	}

	got, err := repo.FindByHash(ctx, token.TokenHash)
	if err != nil {
		t.Fatalf("FindByHash: %v", err)
	}
	if got.ID != token.ID || got.ToolID != toolID {
		t.Fatalf("FindByHash = id %d tool %d, want %d/%d", got.ID, got.ToolID, token.ID, toolID)
	}

	if _, err := repo.FindByHash(ctx, "no-such-hash"); err != service.ErrAccessTokenNotFound {
		t.Fatalf("FindByHash(unknown) error = %v, want ErrAccessTokenNotFound", err)
	}

	list, err := repo.ListByTool(ctx, toolID)
	if err != nil {
		t.Fatalf("ListByTool: %v", err)
	}
	if len(list) != 1 || list[0].ID != token.ID {
		t.Fatalf("ListByTool = %d rows, want exactly the created token", len(list))
	}

	// Cross-tool revoke must fail and mutate nothing.
	if err := repo.Revoke(ctx, toolID+999999, token.ID, now); err != service.ErrAccessTokenNotFound {
		t.Fatalf("Revoke(wrong tool) error = %v, want ErrAccessTokenNotFound", err)
	}
	stillLive, err := repo.FindByHash(ctx, token.TokenHash)
	if err != nil {
		t.Fatalf("FindByHash after wrong-tool revoke: %v", err)
	}
	if stillLive.RevokedAt != nil {
		t.Fatal("token was revoked by a cross-tool request")
	}

	// Correct-tool revoke must succeed and be visible immediately.
	if err := repo.Revoke(ctx, toolID, token.ID, now); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	revoked, err := repo.FindByHash(ctx, token.TokenHash)
	if err != nil {
		t.Fatalf("FindByHash after revoke: %v", err)
	}
	if revoked.RevokedAt == nil {
		t.Fatal("revoked_at is nil after Revoke")
	}

	// Revoking again reports not-found; idempotency is the service's concern.
	if err := repo.Revoke(ctx, toolID, token.ID, now); err != service.ErrAccessTokenNotFound {
		t.Fatalf("second Revoke error = %v, want ErrAccessTokenNotFound", err)
	}

	touchAt := now.Add(time.Minute)
	if err := repo.TouchLastUsed(ctx, token.ID, touchAt); err != nil {
		t.Fatalf("TouchLastUsed: %v", err)
	}
	touched, err := repo.FindByHash(ctx, token.TokenHash)
	if err != nil {
		t.Fatalf("FindByHash after touch: %v", err)
	}
	if touched.LastUsedAt == nil {
		t.Fatal("last_used_at is nil after TouchLastUsed")
	}
}

func TestAccessTokenRepositoryRejectsDuplicateHash(t *testing.T) {
	db := openDevDB(t)
	ctx := context.Background()
	adminID, toolID := seedTokenFixture(t, db)
	repo := repository.NewAccessTokenRepository(db)

	now := time.Now().UTC()
	hash := service.HashToken("tbpbj_dupe_" + now.Format("150405.000000000"))
	first := &model.AccessToken{
		ToolID:           toolID,
		TokenHash:        hash,
		TokenPrefix:      "dupe0001",
		ExpiresAt:        now.Add(time.Hour),
		CreatedByAdminID: adminID,
		CreatedAt:        now,
	}
	if err := repo.Create(ctx, first); err != nil {
		t.Fatalf("first Create: %v", err)
	}

	second := &model.AccessToken{
		ToolID:           toolID,
		TokenHash:        hash,
		TokenPrefix:      "dupe0002",
		ExpiresAt:        now.Add(time.Hour),
		CreatedByAdminID: adminID,
		CreatedAt:        now,
	}
	if err := repo.Create(ctx, second); err != service.ErrAccessTokenHashCollision {
		t.Fatalf("duplicate Create error = %v, want ErrAccessTokenHashCollision", err)
	}
}
