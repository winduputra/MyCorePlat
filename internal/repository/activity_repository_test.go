package repository_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/winduputra/MyCorePlat/internal/model"
	"github.com/winduputra/MyCorePlat/internal/repository"
	"github.com/winduputra/MyCorePlat/internal/service"
)

// uniqueAction keeps parallel test runs from seeing each other's rows.
func uniqueAction(prefix string) string {
	return fmt.Sprintf("%s.%d", prefix, time.Now().UTC().UnixNano())
}

func seedToolForActivity(t *testing.T, db *gorm.DB) *model.Tool {
	t.Helper()
	slug := uniqueSlug(t)
	tool := &model.Tool{
		Slug:            slug,
		Name:            "Activity Fixture Tool",
		AccessType:      model.ToolAccessPublic,
		UpstreamURL:     "http://activity-fixture:8000",
		HealthcheckPath: "/health",
		Status:          model.ToolStatusActive,
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	}
	if err := db.Create(tool).Error; err != nil {
		t.Fatalf("seed tool: %v", err)
	}
	t.Cleanup(func() {
		// activity_logs.tool_id is ON DELETE SET NULL, so the tool can go first.
		_ = db.Unscoped().Where("tool_id = ?", tool.ID).Delete(&model.ActivityLog{}).Error
		_ = db.Unscoped().Where("id = ?", tool.ID).Delete(&model.Tool{}).Error
	})
	return tool
}

func TestActivityLogRepositoryInsertAndList(t *testing.T) {
	db := openDevDB(t)
	repo := repository.NewActivityLogRepository(db)
	ctx := context.Background()

	action := uniqueAction("tool.create")
	tool := seedToolForActivity(t, db)
	meta := `{"slug":"fixture"}`
	entry := &model.ActivityLog{
		ActorType:    model.ActorTypeAdmin,
		Action:       action,
		EntityType:   strPtr(service.EntityTypeTool),
		EntityID:     &tool.ID,
		ToolID:       &tool.ID,
		IPAddress:    strPtr("127.0.0.1"),
		UserAgent:    strPtr("go-test"),
		MetadataJSON: &meta,
		CreatedAt:    time.Now().UTC(),
	}
	if err := repo.Insert(ctx, entry); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if entry.ID == 0 {
		t.Fatal("insert must assign an id")
	}

	rows, total, err := repo.List(ctx, service.ActivityFilter{Action: action, Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 1 || len(rows) != 1 {
		t.Fatalf("expected exactly one row, got total=%d len=%d", total, len(rows))
	}
	got := rows[0]
	if got.Action != action {
		t.Fatalf("unexpected action %q", got.Action)
	}
	if got.MetadataJSON == nil || *got.MetadataJSON != meta {
		t.Fatalf("metadata roundtrip failed: %v", got.MetadataJSON)
	}
	if got.ToolID == nil || *got.ToolID != tool.ID {
		t.Fatal("tool id not persisted")
	}

	t.Cleanup(func() { _ = db.Unscoped().Where("id = ?", entry.ID).Delete(&model.ActivityLog{}).Error })
}

func TestActivityLogRepositoryFiltersAndPaginates(t *testing.T) {
	db := openDevDB(t)
	repo := repository.NewActivityLogRepository(db)
	ctx := context.Background()

	action := uniqueAction("tool.update")
	tool := seedToolForActivity(t, db)

	var ids []uint64
	// Timestamps are built from the wall clock and spaced by minutes, so the
	// range assertions below hold regardless of the DB connection's time zone.
	base := time.Now().Add(-time.Hour)
	for i := 0; i < 5; i++ {
		entry := &model.ActivityLog{
			ActorType:  model.ActorTypeAdmin,
			Action:     action,
			EntityType: strPtr(service.EntityTypeTool),
			ToolID:     &tool.ID,
			CreatedAt:  base.Add(time.Duration(i) * time.Minute),
		}
		if err := repo.Insert(ctx, entry); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
		ids = append(ids, entry.ID)
	}
	t.Cleanup(func() {
		for _, id := range ids {
			_ = db.Unscoped().Where("id = ?", id).Delete(&model.ActivityLog{}).Error
		}
	})

	page1, total, err := repo.List(ctx, service.ActivityFilter{Action: action, Limit: 2, Offset: 0})
	if err != nil {
		t.Fatalf("list page1: %v", err)
	}
	if total != 5 {
		t.Fatalf("expected total 5, got %d", total)
	}
	if len(page1) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(page1))
	}
	// Newest first.
	if !page1[0].CreatedAt.After(page1[1].CreatedAt) {
		t.Fatal("rows are not ordered newest first")
	}

	page3, _, err := repo.List(ctx, service.ActivityFilter{Action: action, Limit: 2, Offset: 4})
	if err != nil {
		t.Fatalf("list page3: %v", err)
	}
	if len(page3) != 1 {
		t.Fatalf("expected 1 row on last page, got %d", len(page3))
	}

	// Tool filter narrows to the fixture tool.
	byTool, _, err := repo.List(ctx, service.ActivityFilter{ToolID: &tool.ID, Limit: 10})
	if err != nil {
		t.Fatalf("list by tool: %v", err)
	}
	for _, row := range byTool {
		if row.ToolID == nil || *row.ToolID != tool.ID {
			t.Fatal("tool filter leaked another tool's rows")
		}
	}

	// Date filter: From is computed from a row read back from the database, so
	// the comparison cannot be skewed by the connection's time zone.
	all, _, err := repo.List(ctx, service.ActivityFilter{Action: action, Limit: 10})
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all) != 5 {
		t.Fatalf("expected 5 rows, got %d", len(all))
	}
	from := all[2].CreatedAt
	inRange, _, err := repo.List(ctx, service.ActivityFilter{Action: action, From: &from, Limit: 10})
	if err != nil {
		t.Fatalf("list by date: %v", err)
	}
	if len(inRange) < 3 || len(inRange) > 4 {
		t.Fatalf("expected 3-4 rows in range, got %d", len(inRange))
	}
}

func TestActivityLogRepositoryToolDeleteKeepsLog(t *testing.T) {
	db := openDevDB(t)
	repo := repository.NewActivityLogRepository(db)
	ctx := context.Background()

	action := uniqueAction("tool.delete")
	tool := seedToolForActivity(t, db)
	entry := &model.ActivityLog{
		ActorType:  model.ActorTypeAdmin,
		Action:     action,
		EntityType: strPtr(service.EntityTypeTool),
		ToolID:     &tool.ID,
		CreatedAt:  time.Now().UTC(),
	}
	if err := repo.Insert(ctx, entry); err != nil {
		t.Fatalf("insert: %v", err)
	}
	t.Cleanup(func() { _ = db.Unscoped().Where("id = ?", entry.ID).Delete(&model.ActivityLog{}).Error })

	// Removing the tool must not delete the audit trail (ON DELETE SET NULL).
	if err := db.Unscoped().Where("id = ?", tool.ID).Delete(&model.Tool{}).Error; err != nil {
		t.Fatalf("delete tool: %v", err)
	}

	rows, total, err := repo.List(ctx, service.ActivityFilter{Action: action, Limit: 5})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 1 || len(rows) != 1 {
		t.Fatalf("audit row lost with the tool: total=%d", total)
	}
	if rows[0].ToolID != nil {
		t.Fatal("tool_id should be NULL after the tool is removed")
	}
}

func strPtr(v string) *string { return &v }
