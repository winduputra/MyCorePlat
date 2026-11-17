package repository_test

import (
	"context"
	"testing"
	"time"

	"github.com/winduputra/MyCorePlat/internal/model"
	"github.com/winduputra/MyCorePlat/internal/repository"
	"github.com/winduputra/MyCorePlat/internal/service"
)

func uniqueSlug(t *testing.T) string {
	t.Helper()
	return "tool-" + time.Now().UTC().Format("20060102150405.000000000")
}

// TestToolRepositoryLifecycle exercises Create/GetByID/GetBySlug/Update/SoftDelete
// against real MariaDB, cleaning up the inserted tool.
func TestToolRepositoryLifecycle(t *testing.T) {
	db := openDevDB(t)
	ctx := context.Background()
	repo := repository.NewToolRepository(db)

	slug := uniqueSlug(t)
	tool := &model.Tool{
		Slug:            slug,
		Name:            "Integration Tool",
		AccessType:      model.ToolAccessPublic,
		UpstreamURL:     "http://integration-tool:8000",
		HealthcheckPath: "/health",
		Status:          model.ToolStatusDraft,
	}
	if err := repo.Create(ctx, tool); err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() {
		// Hard-delete to avoid leaving soft-deleted rows behind.
		db.Unscoped().Where("slug = ?", slug).Delete(&model.Tool{})
	})
	if tool.ID == 0 {
		t.Fatal("Create did not assign an id")
	}

	got, err := repo.GetByID(ctx, tool.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Slug != slug {
		t.Fatalf("GetByID slug = %q, want %q", got.Slug, slug)
	}

	bySlug, err := repo.GetBySlug(ctx, slug)
	if err != nil {
		t.Fatalf("GetBySlug: %v", err)
	}
	if bySlug.ID != tool.ID {
		t.Fatalf("GetBySlug id = %d, want %d", bySlug.ID, tool.ID)
	}

	// Missing rows map to the service sentinel.
	if _, err := repo.GetByID(ctx, 999999999); err != service.ErrToolNotFound {
		t.Fatalf("missing GetByID error = %v, want ErrToolNotFound", err)
	}
	if _, err := repo.GetBySlug(ctx, "no-such-slug-xyz"); err != service.ErrToolNotFound {
		t.Fatalf("missing GetBySlug error = %v, want ErrToolNotFound", err)
	}

	// Update a mutable field.
	got.Name = "Integration Tool Updated"
	got.Description = new("updated description")
	got.DisplayOrder = 5
	if err := repo.Update(ctx, got); err != nil {
		t.Fatalf("Update: %v", err)
	}
	var list []model.Tool
	if err := db.Where("slug = ?", slug).Find(&list).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(list) != 1 || list[0].Name != "Integration Tool Updated" || list[0].DisplayOrder != 5 {
		t.Fatalf("update not persisted: %+v", list)
	}
	if list[0].Description == nil || *list[0].Description != "updated description" {
		t.Fatalf("description not persisted: %+v", list[0].Description)
	}

	// SoftDelete hides the row from normal reads.
	if err := repo.SoftDelete(ctx, tool.ID); err != nil {
		t.Fatalf("SoftDelete: %v", err)
	}
	if _, err := repo.GetByID(ctx, tool.ID); err != service.ErrToolNotFound {
		t.Fatalf("after SoftDelete GetByID error = %v, want ErrToolNotFound", err)
	}

	// SoftDelete of an already-deleted (unscoped-invisible) row reports not found.
	if err := repo.SoftDelete(ctx, tool.ID); err != service.ErrToolNotFound {
		t.Fatalf("second SoftDelete error = %v, want ErrToolNotFound", err)
	}

	// List must not include the soft-deleted tool.
	tools, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, row := range tools {
		if row.ID == tool.ID {
			t.Fatal("soft-deleted tool still appears in List")
		}
	}
}

// TestToolRepositoryDuplicateSlug proves the DB unique constraint surfaces as a
// create error (checked at the service layer, enforced at the DB layer).
func TestToolRepositoryDuplicateSlug(t *testing.T) {
	db := openDevDB(t)
	ctx := context.Background()
	repo := repository.NewToolRepository(db)

	slug := uniqueSlug(t)
	first := &model.Tool{
		Slug:            slug,
		Name:            "First",
		AccessType:      model.ToolAccessPublic,
		UpstreamURL:     "http://dup-tool:8000",
		HealthcheckPath: "/health",
		Status:          model.ToolStatusDraft,
	}
	if err := repo.Create(ctx, first); err != nil {
		t.Fatalf("Create first: %v", err)
	}
	t.Cleanup(func() {
		db.Unscoped().Where("slug = ?", slug).Delete(&model.Tool{})
	})

	second := &model.Tool{
		Slug:            slug,
		Name:            "Second",
		AccessType:      model.ToolAccessPublic,
		UpstreamURL:     "http://dup-tool-2:8000",
		HealthcheckPath: "/health",
		Status:          model.ToolStatusDraft,
	}
	if err := repo.Create(ctx, second); err == nil {
		t.Fatal("Create with duplicate slug succeeded, want unique-constraint error")
	}
}
