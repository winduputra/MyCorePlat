package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/winduputra/MyCorePlat/internal/model"
)

type fakeActivityRepo struct {
	rows       []*model.ActivityLog
	insertErr  error
	insertCall int
	lastFilter ActivityFilter
}

func (f *fakeActivityRepo) Insert(_ context.Context, entry *model.ActivityLog) error {
	f.insertCall++
	if f.insertErr != nil {
		return f.insertErr
	}
	entry.ID = uint64(len(f.rows) + 1)
	f.rows = append(f.rows, entry)
	return nil
}

func (f *fakeActivityRepo) List(_ context.Context, filter ActivityFilter) ([]model.ActivityLog, int64, error) {
	f.lastFilter = filter
	out := make([]model.ActivityLog, 0, len(f.rows))
	for _, row := range f.rows {
		out = append(out, *row)
	}
	return out, int64(len(out)), nil
}

func newActivityService(repo ActivityLogRepository, limit int) *ActivityService {
	return NewActivityService(repo, limit)
}

func TestActivityRecordPersistsCoreFields(t *testing.T) {
	repo := &fakeActivityRepo{}
	svc := newActivityService(repo, 0)

	adminID := uint64(7)
	toolID := uint64(3)
	ok := svc.Record(context.Background(), ActivityEntry{
		ActorType:  model.ActorTypeAdmin,
		ActorID:    &adminID,
		Action:     ActionToolCreated,
		EntityType: EntityTypeTool,
		EntityID:   &toolID,
		ToolID:     &toolID,
		IPAddress:  "203.0.113.9",
		UserAgent:  "unit-test",
	})

	if !ok {
		t.Fatal("Record reported failure for a valid entry")
	}
	if len(repo.rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(repo.rows))
	}
	row := repo.rows[0]
	if row.ActorType != model.ActorTypeAdmin || row.Action != ActionToolCreated {
		t.Fatalf("unexpected row: %+v", row)
	}
	if row.ActorID == nil || *row.ActorID != adminID {
		t.Fatal("actor id not persisted")
	}
	if row.ToolID == nil || *row.ToolID != toolID {
		t.Fatal("tool id not persisted")
	}
	if row.EntityType == nil || *row.EntityType != EntityTypeTool {
		t.Fatal("entity type not persisted")
	}
	if row.CreatedAt.IsZero() {
		t.Fatal("created_at must be set explicitly")
	}
}

func TestActivityRecordDropsSensitiveMetadataKeys(t *testing.T) {
	repo := &fakeActivityRepo{}
	svc := newActivityService(repo, 0)

	svc.Record(context.Background(), ActivityEntry{
		ActorType: model.ActorTypeAdmin,
		Action:    ActionTokenCreated,
		Metadata: map[string]any{
			"token_plaintext": "tbpbj_abc_secretsecretsecret",
			"token_hash":      "deadbeef",
			"password":        "hunter2",
			"Authorization":   "Bearer abc",
			"Cookie":          "bpbj_admin_session=xyz",
			"csrf_token":      "csrf-value",
			"X-Signature":     "sigvalue",
			"hmac_secret":     "shh",
			"dsn":             "user:pw@tcp(host)/db",
			"session_id":      "abc",
			"tool_slug":       "image-compressor",
			"recipient_label": "Dinas A",
			"expires_in_days": 30,
		},
	})

	if len(repo.rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(repo.rows))
	}
	row := repo.rows[0]
	if row.MetadataJSON == nil {
		t.Fatal("metadata should survive with only safe keys")
	}
	raw := strings.ToLower(*row.MetadataJSON)
	for _, forbidden := range []string{"tbpbj", "deadbeef", "hunter2", "bearer abc", "bpbj_admin_session", "csrf-value", "sigvalue", "shh", "tcp(", "abc\""} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("sensitive value %q leaked into metadata: %s", forbidden, raw)
		}
	}
	for _, expected := range []string{"tool_slug", "recipient_label", "expires_in_days"} {
		if !strings.Contains(raw, expected) {
			t.Fatalf("expected safe key %q in metadata: %s", expected, raw)
		}
	}
}

func TestActivityRecordOmitsMetadataWhenAllKeysAreSensitive(t *testing.T) {
	repo := &fakeActivityRepo{}
	svc := newActivityService(repo, 0)

	svc.Record(context.Background(), ActivityEntry{
		Action: ActionAdminLogin,
		Metadata: map[string]any{
			"password":    "x",
			"token":       "y",
			"cookie":      "z",
			"X-Signature": "s",
		},
	})

	if len(repo.rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(repo.rows))
	}
	if repo.rows[0].MetadataJSON != nil {
		t.Fatalf("metadata should be nil, got %s", *repo.rows[0].MetadataJSON)
	}
}

func TestActivityRecordBoundsMetadataSize(t *testing.T) {
	repo := &fakeActivityRepo{}
	svc := newActivityService(repo, 64)

	big := strings.Repeat("a", 500)
	svc.Record(context.Background(), ActivityEntry{
		Action: ActionToolUpdated,
		Metadata: map[string]any{
			"note":  big,
			"note2": big,
			"note3": big,
		},
	})

	if len(repo.rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(repo.rows))
	}
	raw := *repo.rows[0].MetadataJSON
	if len(raw) > 128 {
		t.Fatalf("metadata not bounded: len=%d value=%s", len(raw), raw)
	}
	if !json.Valid([]byte(raw)) {
		t.Fatalf("metadata is not valid JSON: %s", raw)
	}
}

func TestActivityRecordTruncatesLongStrings(t *testing.T) {
	repo := &fakeActivityRepo{}
	svc := newActivityService(repo, 0)

	svc.Record(context.Background(), ActivityEntry{
		Action:    ActionToolUpdated,
		UserAgent: strings.Repeat("u", 900),
		IPAddress: strings.Repeat("1", 60),
		Metadata:  map[string]any{"note": strings.Repeat("n", 900)},
	})

	row := repo.rows[0]
	if row.UserAgent == nil || len(*row.UserAgent) > maxUserAgentLen {
		t.Fatalf("user agent not truncated: %v", row.UserAgent)
	}
	if row.IPAddress == nil || len(*row.IPAddress) > maxIPAddressLen {
		t.Fatalf("ip address not truncated: %v", row.IPAddress)
	}
	var meta map[string]any
	if err := json.Unmarshal([]byte(*row.MetadataJSON), &meta); err != nil {
		t.Fatalf("metadata invalid: %v", err)
	}
	note, _ := meta["note"].(string)
	if len(note) > maxMetadataStringLen {
		t.Fatalf("metadata string not truncated: %d", len(note))
	}
}

func TestActivityRecordNeverFailsCallerWhenStorageFails(t *testing.T) {
	repo := &fakeActivityRepo{insertErr: errors.New("boom: dsn user:pw@tcp(secret-host)/db")}
	svc := newActivityService(repo, 0)

	if svc.Record(context.Background(), ActivityEntry{Action: ActionAdminLogin}) {
		t.Fatal("expected Record to report failure")
	}
	if repo.insertCall != 1 {
		t.Fatalf("expected one insert attempt, got %d", repo.insertCall)
	}
}

func TestActivityRecordRejectsEmptyAction(t *testing.T) {
	repo := &fakeActivityRepo{}
	svc := newActivityService(repo, 0)

	if svc.Record(context.Background(), ActivityEntry{ActorType: model.ActorTypeAdmin}) {
		t.Fatal("expected empty action to be rejected")
	}
	if repo.insertCall != 0 {
		t.Fatalf("repository should not be called, got %d", repo.insertCall)
	}
}

func TestActivityRecordDoesNotPanicWithNilService(t *testing.T) {
	var svc *ActivityService
	if svc.Record(context.Background(), ActivityEntry{Action: ActionAdminLogin}) {
		t.Fatal("nil service must not report success")
	}
}

func TestActivityRecordDefaultsActorType(t *testing.T) {
	repo := &fakeActivityRepo{}
	svc := newActivityService(repo, 0)

	svc.Record(context.Background(), ActivityEntry{Action: ActionHealthCheckFailed, ActorType: "unknown"})
	if repo.rows[0].ActorType != model.ActorTypeSystem {
		t.Fatalf("expected system actor fallback, got %q", repo.rows[0].ActorType)
	}
}

func TestActivityListAppliesPagingBounds(t *testing.T) {
	repo := &fakeActivityRepo{}
	svc := newActivityService(repo, 0)

	_, _, err := svc.List(context.Background(), ActivityFilter{Limit: 0, Offset: -5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if repo.lastFilter.Limit != DefaultActivityPageSize {
		t.Fatalf("expected default page size, got %d", repo.lastFilter.Limit)
	}
	if repo.lastFilter.Offset != 0 {
		t.Fatalf("expected zero offset, got %d", repo.lastFilter.Offset)
	}

	_, _, _ = svc.List(context.Background(), ActivityFilter{Limit: 10000})
	if repo.lastFilter.Limit != MaxActivityPageSize {
		t.Fatalf("expected capped page size, got %d", repo.lastFilter.Limit)
	}
}

func TestActivityListPassesFiltersThrough(t *testing.T) {
	repo := &fakeActivityRepo{}
	svc := newActivityService(repo, 0)

	toolID := uint64(9)
	from := time.Now().Add(-24 * time.Hour).UTC()
	to := time.Now().UTC()
	_, _, _ = svc.List(context.Background(), ActivityFilter{
		Action:     ActionTokenRevoked,
		EntityType: EntityTypeToken,
		ToolID:     &toolID,
		From:       &from,
		To:         &to,
		Limit:      10,
		Offset:     20,
	})

	got := repo.lastFilter
	if got.Action != ActionTokenRevoked || got.EntityType != EntityTypeToken {
		t.Fatalf("filters not passed: %+v", got)
	}
	if got.ToolID == nil || *got.ToolID != toolID {
		t.Fatal("tool filter not passed")
	}
	if got.From == nil || got.To == nil {
		t.Fatal("date filters not passed")
	}
	if got.Offset != 20 {
		t.Fatalf("offset not passed: %d", got.Offset)
	}
}

func TestActivityMetadataBoundFallsBackToConservativeDefault(t *testing.T) {
	svc := NewActivityService(&fakeActivityRepo{}, -1)
	if svc.metadataLimit != DefaultActivityMetadataLimit {
		t.Fatalf("expected default limit, got %d", svc.metadataLimit)
	}
}
