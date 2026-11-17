package service

import (
	"context"
	"strings"
	"testing"

	"github.com/winduputra/MyCorePlat/internal/model"
)

// fakeToolRepo is an in-memory ToolRepository for unit tests.
type fakeToolRepo struct {
	byID      map[uint64]*model.Tool
	bySlug    map[string]*model.Tool
	nextID    uint64
	createErr error
	updateErr error
	deleteErr error
}

func newFakeToolRepo() *fakeToolRepo {
	return &fakeToolRepo{byID: map[uint64]*model.Tool{}, bySlug: map[string]*model.Tool{}, nextID: 1}
}

func (f *fakeToolRepo) List(_ context.Context) ([]model.Tool, error) {
	out := make([]model.Tool, 0, len(f.byID))
	for _, t := range f.byID {
		out = append(out, *t)
	}
	return out, nil
}

func (f *fakeToolRepo) GetByID(_ context.Context, id uint64) (*model.Tool, error) {
	t, ok := f.byID[id]
	if !ok {
		return nil, ErrToolNotFound
	}
	copied := *t
	return &copied, nil
}

func (f *fakeToolRepo) GetBySlug(_ context.Context, slug string) (*model.Tool, error) {
	t, ok := f.bySlug[slug]
	if !ok {
		return nil, ErrToolNotFound
	}
	copied := *t
	return &copied, nil
}

func (f *fakeToolRepo) Create(_ context.Context, tool *model.Tool) error {
	if f.createErr != nil {
		return f.createErr
	}
	tool.ID = f.nextID
	f.nextID++
	stored := *tool
	f.byID[tool.ID] = &stored
	f.bySlug[tool.Slug] = &stored
	return nil
}

func (f *fakeToolRepo) Update(_ context.Context, tool *model.Tool) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	if _, ok := f.byID[tool.ID]; !ok {
		return ErrToolNotFound
	}
	stored := *tool
	f.byID[tool.ID] = &stored
	f.bySlug[tool.Slug] = &stored
	return nil
}

func (f *fakeToolRepo) SoftDelete(_ context.Context, id uint64) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	t, ok := f.byID[id]
	if !ok {
		return ErrToolNotFound
	}
	delete(f.byID, id)
	delete(f.bySlug, t.Slug)
	return nil
}

func validToolInput() ToolInput {
	return ToolInput{
		Slug:            "image-compressor",
		Name:            "Image Compressor",
		UpstreamURL:     "http://image-compressor:8000",
		Description:     "Compress images",
		AccessType:      "public",
		Status:          "draft",
		HealthcheckPath: "/health",
	}
}

func TestToolServiceCreateSuccess(t *testing.T) {
	svc := NewToolService(newFakeToolRepo(), testAllowlist())
	tool, err := svc.Create(context.Background(), validToolInput())
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if tool.ID == 0 {
		t.Fatal("Create did not assign an id")
	}
	if tool.Slug != "image-compressor" {
		t.Errorf("slug = %q", tool.Slug)
	}
	if tool.Status != model.ToolStatusDraft {
		t.Errorf("status = %q, want draft", tool.Status)
	}
	if tool.HealthcheckPath != "/health" {
		t.Errorf("healthcheck = %q", tool.HealthcheckPath)
	}
}

func TestToolServiceCreateRejectsDuplicateSlug(t *testing.T) {
	svc := NewToolService(newFakeToolRepo(), testAllowlist())
	if _, err := svc.Create(context.Background(), validToolInput()); err != nil {
		t.Fatalf("first Create error: %v", err)
	}
	_, err := svc.Create(context.Background(), validToolInput())
	if err == nil {
		t.Fatal("duplicate slug was accepted")
	}
	if !strings.Contains(err.Error(), "slug") {
		t.Errorf("error = %v, want slug-related", err)
	}
}

func TestToolServiceCreateRejectsPublicUpstream(t *testing.T) {
	svc := NewToolService(newFakeToolRepo(), testAllowlist())
	in := validToolInput()
	in.UpstreamURL = "https://example.com/x"
	if _, err := svc.Create(context.Background(), in); err == nil {
		t.Fatal("public upstream was accepted")
	}
}

func TestToolServiceCreateRejectsInvalidSlug(t *testing.T) {
	svc := NewToolService(newFakeToolRepo(), testAllowlist())
	in := validToolInput()
	in.Slug = "Bad Slug!"
	if _, err := svc.Create(context.Background(), in); err == nil {
		t.Fatal("invalid slug was accepted")
	}
}

func TestToolServiceCreateRejectsEmptyName(t *testing.T) {
	svc := NewToolService(newFakeToolRepo(), testAllowlist())
	in := validToolInput()
	in.Name = "  "
	if _, err := svc.Create(context.Background(), in); err == nil {
		t.Fatal("empty name was accepted")
	}
}

func TestToolServiceCreateRejectsInvalidStatus(t *testing.T) {
	svc := NewToolService(newFakeToolRepo(), testAllowlist())
	in := validToolInput()
	in.Status = "bogus"
	if _, err := svc.Create(context.Background(), in); err == nil {
		t.Fatal("invalid status was accepted")
	}
}

func TestToolServiceCreateRejectsInvalidAccess(t *testing.T) {
	svc := NewToolService(newFakeToolRepo(), testAllowlist())
	in := validToolInput()
	in.AccessType = "secret"
	if _, err := svc.Create(context.Background(), in); err == nil {
		t.Fatal("invalid access type was accepted")
	}
}

func TestToolServiceListAndGet(t *testing.T) {
	svc := NewToolService(newFakeToolRepo(), testAllowlist())
	created, err := svc.Create(context.Background(), validToolInput())
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	list, err := svc.List(context.Background())
	if err != nil {
		t.Fatalf("List error: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("list len = %d, want 1", len(list))
	}
	got, err := svc.Get(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("Get error: %v", err)
	}
	if got.Slug != created.Slug {
		t.Errorf("got slug %q, want %q", got.Slug, created.Slug)
	}
}

func TestToolServiceGetNotFound(t *testing.T) {
	svc := NewToolService(newFakeToolRepo(), testAllowlist())
	if _, err := svc.Get(context.Background(), 999); err != ErrToolNotFound {
		t.Fatalf("error = %v, want ErrToolNotFound", err)
	}
}

func TestToolServiceUpdateSuccess(t *testing.T) {
	svc := NewToolService(newFakeToolRepo(), testAllowlist())
	created, _ := svc.Create(context.Background(), validToolInput())
	in := validToolInput()
	in.Name = "Image Compressor v2"
	in.UpstreamURL = "http://image-compressor:8080"
	updated, err := svc.Update(context.Background(), created.ID, in)
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if updated.Name != "Image Compressor v2" {
		t.Errorf("name = %q", updated.Name)
	}
	if updated.UpstreamURL != "http://image-compressor:8080" {
		t.Errorf("upstream = %q", updated.UpstreamURL)
	}
}

func TestToolServiceUpdateNotFound(t *testing.T) {
	svc := NewToolService(newFakeToolRepo(), testAllowlist())
	if _, err := svc.Update(context.Background(), 123, validToolInput()); err != ErrToolNotFound {
		t.Fatalf("error = %v, want ErrToolNotFound", err)
	}
}

func TestToolServiceDeleteSuccess(t *testing.T) {
	svc := NewToolService(newFakeToolRepo(), testAllowlist())
	created, _ := svc.Create(context.Background(), validToolInput())
	if err := svc.Delete(context.Background(), created.ID); err != nil {
		t.Fatalf("Delete error: %v", err)
	}
	if _, err := svc.Get(context.Background(), created.ID); err != ErrToolNotFound {
		t.Fatalf("after delete, Get error = %v, want ErrToolNotFound", err)
	}
}

func TestToolServiceDeleteNotFound(t *testing.T) {
	svc := NewToolService(newFakeToolRepo(), testAllowlist())
	if err := svc.Delete(context.Background(), 55); err != ErrToolNotFound {
		t.Fatalf("error = %v, want ErrToolNotFound", err)
	}
}

// TestToolServiceImportManifestCannotOverrideStatus asserts that importing a
// manifest never changes the DB-managed status/access beyond explicit admin
// input.
func TestToolServiceImportManifestCannotOverrideStatus(t *testing.T) {
	svc := NewToolService(newFakeToolRepo(), testAllowlist())
	tool, err := svc.ImportManifest(context.Background(), []byte(validManifest))
	if err != nil {
		t.Fatalf("ImportManifest error: %v", err)
	}
	if tool.Status != model.ToolStatusDraft {
		t.Errorf("status = %q, want draft (never active from manifest)", tool.Status)
	}
	if tool.AccessType != model.ToolAccessPublic {
		t.Errorf("access = %q", tool.AccessType)
	}
}

func TestToolServiceImportManifestRejectsInvalid(t *testing.T) {
	svc := NewToolService(newFakeToolRepo(), testAllowlist())
	if _, err := svc.ImportManifest(context.Background(), []byte(`{"id":"x"}`)); err == nil {
		t.Fatal("invalid manifest was accepted")
	}
}
