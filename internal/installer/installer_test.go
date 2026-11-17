package installer

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/winduputra/MyCorePlat/internal/model"
)

// --- test fakes -------------------------------------------------------------

type fakeBuilder struct {
	mu         sync.Mutex
	buildCalls int
	removeCall []string
	buildErr   error
	tag        string
}

func (f *fakeBuilder) Build(_ context.Context, slug, version, _ string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.buildCalls++
	if f.buildErr != nil {
		return "", f.buildErr
	}
	f.tag = "tools-bpbj/" + slug + ":" + version
	return f.tag, nil
}

func (f *fakeBuilder) Remove(_ context.Context, tag string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removeCall = append(f.removeCall, tag)
	return nil
}

type fakeRunner struct {
	mu           sync.Mutex
	runErr       error
	healthySeq   []bool
	healthyIdx   int
	stopped      []string
	removed      []string
	lastSpec     ContainerSpec
	healthyErr   error
	neverHealthy bool
}

func (f *fakeRunner) Run(_ context.Context, spec ContainerSpec) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastSpec = spec
	if f.runErr != nil {
		return "", f.runErr
	}
	return spec.ContainerName, nil
}

func (f *fakeRunner) Stop(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopped = append(f.stopped, name)
	return nil
}

func (f *fakeRunner) Remove(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, name)
	return nil
}

func (f *fakeRunner) Healthy(_ context.Context, _ string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.healthyErr != nil {
		return false, f.healthyErr
	}
	if f.neverHealthy {
		return false, nil
	}
	if f.healthyIdx < len(f.healthySeq) {
		v := f.healthySeq[f.healthyIdx]
		f.healthyIdx++
		return v, nil
	}
	return true, nil
}

type fakeSecrets struct {
	provisionErr error
	revoked      []string
	provisioned  []string
}

func (f *fakeSecrets) Provision(_ context.Context, slug string) (string, error) {
	if f.provisionErr != nil {
		return "", f.provisionErr
	}
	f.provisioned = append(f.provisioned, slug)
	return "k-test", nil
}

func (f *fakeSecrets) Revoke(_ context.Context, slug string) error {
	f.revoked = append(f.revoked, slug)
	return nil
}

type fakeRegistrar struct {
	registerErr error
	registered  []string
	removed     []string
	toolID      uint64
}

func (f *fakeRegistrar) Register(_ context.Context, m Manifest, _ string) (uint64, error) {
	if f.registerErr != nil {
		return 0, f.registerErr
	}
	f.registered = append(f.registered, m.ID)
	if f.toolID == 0 {
		return 42, nil
	}
	return f.toolID, nil
}

func (f *fakeRegistrar) SetStatus(_ context.Context, _, _ string) error { return nil }
func (f *fakeRegistrar) Remove(_ context.Context, slug string) error {
	f.removed = append(f.removed, slug)
	return nil
}

type fakeRecords struct {
	mu      sync.Mutex
	bySlug  map[string]*InstallRecord
	nextID  uint64
	listErr error
}

func newFakeRecords() *fakeRecords {
	return &fakeRecords{bySlug: map[string]*InstallRecord{}}
}

func (f *fakeRecords) Create(_ context.Context, rec *InstallRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	rec.ID = f.nextID
	cp := *rec
	f.bySlug[rec.Slug] = &cp
	return nil
}

func (f *fakeRecords) Update(_ context.Context, rec *InstallRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *rec
	f.bySlug[rec.Slug] = &cp
	return nil
}

func (f *fakeRecords) BySlug(_ context.Context, slug string) (*InstallRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if rec, ok := f.bySlug[slug]; ok {
		cp := *rec
		return &cp, nil
	}
	return nil, ErrNotInstalled
}

func (f *fakeRecords) List(_ context.Context) ([]InstallRecord, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]InstallRecord, 0, len(f.bySlug))
	for _, rec := range f.bySlug {
		out = append(out, *rec)
	}
	return out, nil
}

func (f *fakeRecords) Delete(_ context.Context, slug string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.bySlug, slug)
	return nil
}

// --- helpers ----------------------------------------------------------------

func testPackage(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	manifest := `{"id":"demo-tool","name":"Demo Tool","version":"1.0.0","description":"A demo tool","access":"public","runtime":"python","upstream":"http://demo-tool:8000","healthcheck":"/health"}`
	write := func(name, content string) {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	write("manifest.json", manifest)
	write("Dockerfile", "FROM scratch\n")
	write("app/main.py", "print('hi')\n")
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

func newTestInstaller(t *testing.T, b ImageBuilder, r ContainerRunner, s SecretProvisioner, reg ToolRegistrar, recs InstallRecordStore, now func() time.Time) *Installer {
	t.Helper()
	in, err := New(b, r, s, reg, recs, Options{
		Network: "tools", HMACKeysDir: filepath.Join(t.TempDir(), "tool-hmac"), WorkDir: t.TempDir(),
		HealthTimeout: 2 * time.Second, HealthPollInterval: time.Millisecond, Now: now,
		MemoryLimitMiB: 512, CPULimit: 1.0, PidsLimit: 128,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return in
}

func fixedNow() time.Time { return time.Date(2026, 11, 18, 8, 0, 0, 0, time.UTC) }

// --- tests ------------------------------------------------------------------

func TestInstallHappyPath(t *testing.T) {
	b := &fakeBuilder{}
	r := &fakeRunner{}
	s := &fakeSecrets{}
	reg := &fakeRegistrar{}
	recs := newFakeRecords()
	in := newTestInstaller(t, b, r, s, reg, recs, fixedNow)

	rec, err := in.Install(context.Background(), InstallRequest{PackageBytes: testPackage(t), AdminID: 7})
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if rec.Status != model.ToolInstallInstalled {
		t.Fatalf("status = %q, want installed", rec.Status)
	}
	if rec.ToolID != 42 {
		t.Fatalf("tool id = %d, want 42", rec.ToolID)
	}
	if rec.ContainerName != "tools-demo-tool" {
		t.Fatalf("container = %q", rec.ContainerName)
	}
	if b.buildCalls != 1 {
		t.Fatalf("buildCalls = %d", b.buildCalls)
	}
	if len(reg.registered) != 1 || reg.registered[0] != "demo-tool" {
		t.Fatalf("registered = %v", reg.registered)
	}
	if r.lastSpec.Network != "tools" || r.lastSpec.InternalPort != 8000 {
		t.Fatalf("spec = %+v", r.lastSpec)
	}
	if r.lastSpec.MemoryLimitMiB != 512 || r.lastSpec.PidsLimit != 128 {
		t.Fatalf("limits not applied: %+v", r.lastSpec)
	}
}

func TestInstallRejectsInvalidPackage(t *testing.T) {
	in := newTestInstaller(t, &fakeBuilder{}, &fakeRunner{}, &fakeSecrets{}, &fakeRegistrar{}, newFakeRecords(), fixedNow)
	_, err := in.Install(context.Background(), InstallRequest{PackageBytes: []byte("not a zip")})
	if !errors.Is(err, ErrPackageInvalid) {
		t.Fatalf("err = %v, want ErrPackageInvalid", err)
	}
}

func TestInstallRollsBackOnBuildFailure(t *testing.T) {
	b := &fakeBuilder{buildErr: errors.New("syntax error")}
	r := &fakeRunner{}
	s := &fakeSecrets{}
	recs := newFakeRecords()
	in := newTestInstaller(t, b, r, s, &fakeRegistrar{}, recs, fixedNow)

	rec, err := in.Install(context.Background(), InstallRequest{PackageBytes: testPackage(t)})
	if !errors.Is(err, ErrBuildFailed) {
		t.Fatalf("err = %v, want ErrBuildFailed", err)
	}
	if rec.Status != model.ToolInstallFailed || rec.ErrorCode != "build" {
		t.Fatalf("record = %+v", rec)
	}
	if len(r.removed) != 0 {
		t.Fatalf("no container should have been created: %v", r.removed)
	}
}

func TestInstallRollsBackOnRunFailure(t *testing.T) {
	b := &fakeBuilder{}
	r := &fakeRunner{runErr: errors.New("port in use")}
	s := &fakeSecrets{}
	recs := newFakeRecords()
	in := newTestInstaller(t, b, r, s, &fakeRegistrar{}, recs, fixedNow)

	rec, err := in.Install(context.Background(), InstallRequest{PackageBytes: testPackage(t)})
	if !errors.Is(err, ErrRunFailed) {
		t.Fatalf("err = %v, want ErrRunFailed", err)
	}
	if rec.Status != model.ToolInstallFailed || rec.ErrorCode != "run" {
		t.Fatalf("record = %+v", rec)
	}
	if len(b.removeCall) != 1 {
		t.Fatalf("image should be rolled back, removeCall = %v", b.removeCall)
	}
	if len(s.revoked) != 1 {
		t.Fatalf("secret should be revoked, revoked = %v", s.revoked)
	}
}

func TestInstallRollsBackOnUnhealthy(t *testing.T) {
	b := &fakeBuilder{}
	r := &fakeRunner{neverHealthy: true}
	s := &fakeSecrets{}
	recs := newFakeRecords()
	// Clock that jumps past the health timeout quickly.
	base := fixedNow()
	nowFn := func() time.Time { return base }
	in := newTestInstaller(t, b, r, s, &fakeRegistrar{}, recs, nowFn)
	in.opts.HealthTimeout = 0 // any poll after the first expires immediately

	rec, err := in.Install(context.Background(), InstallRequest{PackageBytes: testPackage(t)})
	if !errors.Is(err, ErrUnhealthy) {
		t.Fatalf("err = %v, want ErrUnhealthy", err)
	}
	if rec.ErrorCode != "health" {
		t.Fatalf("error code = %q", rec.ErrorCode)
	}
	if len(r.stopped) != 1 || len(r.removed) != 1 {
		t.Fatalf("container should be stopped+removed: stop=%v rm=%v", r.stopped, r.removed)
	}
	if len(b.removeCall) != 1 {
		t.Fatalf("image should be rolled back")
	}
}

func TestInstallRollsBackOnRegistrationFailure(t *testing.T) {
	b := &fakeBuilder{}
	r := &fakeRunner{}
	s := &fakeSecrets{}
	reg := &fakeRegistrar{registerErr: errors.New("db down")}
	recs := newFakeRecords()
	in := newTestInstaller(t, b, r, s, reg, recs, fixedNow)

	rec, err := in.Install(context.Background(), InstallRequest{PackageBytes: testPackage(t)})
	if !errors.Is(err, ErrRegistrationFailed) {
		t.Fatalf("err = %v, want ErrRegistrationFailed", err)
	}
	if rec.ErrorCode != "register" {
		t.Fatalf("error code = %q", rec.ErrorCode)
	}
	if len(r.removed) != 1 {
		t.Fatalf("container should be removed on register failure")
	}
	if len(b.removeCall) != 1 {
		t.Fatalf("image should be removed on register failure")
	}
}

func TestInstallRejectsDuplicateSlug(t *testing.T) {
	recs := newFakeRecords()
	recs.bySlug["demo-tool"] = &InstallRecord{Slug: "demo-tool", Status: model.ToolInstallInstalled}
	in := newTestInstaller(t, &fakeBuilder{}, &fakeRunner{}, &fakeSecrets{}, &fakeRegistrar{}, recs, fixedNow)

	_, err := in.Install(context.Background(), InstallRequest{PackageBytes: testPackage(t)})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
}

func TestUninstallHappyPath(t *testing.T) {
	b := &fakeBuilder{}
	r := &fakeRunner{}
	s := &fakeSecrets{}
	reg := &fakeRegistrar{}
	recs := newFakeRecords()
	recs.bySlug["demo-tool"] = &InstallRecord{Slug: "demo-tool", Status: model.ToolInstallInstalled, ContainerName: "tools-demo-tool", ImageTag: "tools-bpbj/demo-tool:1.0.0"}
	in := newTestInstaller(t, b, r, s, reg, recs, fixedNow)

	if err := in.Uninstall(context.Background(), "demo-tool"); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	rec, _ := recs.BySlug(context.Background(), "demo-tool")
	if rec.Status != model.ToolInstallRemoved {
		t.Fatalf("status = %q", rec.Status)
	}
	if len(r.stopped) != 1 || len(r.removed) != 1 {
		t.Fatalf("container should be stopped+removed")
	}
	if len(reg.removed) != 1 {
		t.Fatalf("registrar should remove tool")
	}
	if len(s.revoked) != 1 {
		t.Fatalf("secret should be revoked")
	}
}

func TestUninstallUnknownSlug(t *testing.T) {
	in := newTestInstaller(t, &fakeBuilder{}, &fakeRunner{}, &fakeSecrets{}, &fakeRegistrar{}, newFakeRecords(), fixedNow)
	err := in.Uninstall(context.Background(), "ghost")
	if !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("err = %v, want ErrNotInstalled", err)
	}
}

func TestPortFromUpstream(t *testing.T) {
	cases := map[string]int{
		"http://demo-tool:8000": 8000,
		"http://demo-tool:3000": 3000,
		"http://demo-tool":      8000,
		"http://demo-tool:abc":  8000,
		"":                      8000,
	}
	for raw, want := range cases {
		if got := portFromUpstream(raw); got != want {
			t.Errorf("portFromUpstream(%q) = %d, want %d", raw, got, want)
		}
	}
}

func TestIsValidSlug(t *testing.T) {
	valid := []string{"pdf-compressor", "a", "tool-1", "abc-def-ghi"}
	invalid := []string{"", "-tool", "tool-", "Tool", "tool_name", "tool_", "a--b"}
	for _, s := range valid {
		if !IsValidSlug(s) {
			t.Errorf("IsValidSlug(%q) = false, want true", s)
		}
	}
	for _, s := range invalid {
		if IsValidSlug(s) {
			t.Errorf("IsValidSlug(%q) = true, want false", s)
		}
	}
}

func TestInstallExtractsNothingOnReject(t *testing.T) {
	// A package whose manifest is invalid must not create a build context.
	dir := t.TempDir()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("manifest.json")
	w.Write([]byte(`{"id":"Bad_ID","name":"x","version":"1.0.0","description":"d","access":"public","runtime":"python","upstream":"http://x:8000","healthcheck":"/health"}`))
	w2, _ := zw.Create("Dockerfile")
	w2.Write([]byte("FROM scratch\n"))
	zw.Close()

	in := newTestInstaller(t, &fakeBuilder{}, &fakeRunner{}, &fakeSecrets{}, &fakeRegistrar{}, newFakeRecords(), fixedNow)
	in.opts.WorkDir = dir
	_, err := in.Install(context.Background(), InstallRequest{PackageBytes: buf.Bytes()})
	if !errors.Is(err, ErrPackageInvalid) {
		t.Fatalf("err = %v", err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("work dir should be empty, got %v", entries)
	}
}
