package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/winduputra/MyCorePlat/internal/model"
)

type fakeHealthTargets struct {
	slugs []string
	tools map[string]*model.Tool
}

func (f *fakeHealthTargets) ListActiveSlugs(context.Context) ([]string, error) {
	return f.slugs, nil
}

func (f *fakeHealthTargets) GetForHealth(_ context.Context, slug string) (*model.Tool, error) {
	tool, ok := f.tools[slug]
	if !ok {
		return nil, ErrToolNotFound
	}
	return tool, nil
}

type fakeHealthRepo struct {
	mu     sync.Mutex
	rows   []model.ToolHealthCheck
	prev   map[uint64]string
	err    error
	insert int32
}

func (f *fakeHealthRepo) Insert(_ context.Context, check *model.ToolHealthCheck) error {
	atomic.AddInt32(&f.insert, 1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	check.ID = uint64(len(f.rows) + 1)
	f.rows = append(f.rows, *check)
	if f.prev == nil {
		f.prev = map[uint64]string{}
	}
	f.prev[check.ToolID] = check.Status
	return nil
}

func (f *fakeHealthRepo) LatestByTool(context.Context, []uint64) (map[uint64]*model.ToolHealthCheck, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[uint64]*model.ToolHealthCheck{}
	for i := range f.rows {
		row := f.rows[i]
		if _, ok := out[row.ToolID]; !ok {
			out[row.ToolID] = &row
		}
	}
	return out, nil
}

func (f *fakeHealthRepo) ListByTool(context.Context, uint64, int) ([]model.ToolHealthCheck, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]model.ToolHealthCheck(nil), f.rows...), nil
}

func (f *fakeHealthRepo) PreviousStatus(_ context.Context, toolID uint64) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.prev == nil {
		return "", nil
	}
	return f.prev[toolID], nil
}

func (f *fakeHealthRepo) rowsSnapshot() []model.ToolHealthCheck {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]model.ToolHealthCheck(nil), f.rows...)
}

func healthTool(id uint64, slug, upstream string) *model.Tool {
	return &model.Tool{
		ID:              id,
		Slug:            slug,
		Name:            slug,
		Status:          model.ToolStatusActive,
		AccessType:      model.ToolAccessPublic,
		UpstreamURL:     upstream,
		HealthcheckPath: "/health",
	}
}

// newHealthCheckerForTest wires a checker whose probes target an httptest
// server. SSRF validation is bypassed only for the dialer, never for the URL
// shape, so the probe still exercises the real client path.
func newHealthCheckerForTest(t *testing.T, tools []*model.Tool, repo ToolHealthRepository, activity *ActivityService, opts HealthCheckOptions) *HealthChecker {
	t.Helper()
	targets := &fakeHealthTargets{tools: map[string]*model.Tool{}}
	for _, tool := range tools {
		targets.tools[tool.Slug] = tool
		targets.slugs = append(targets.slugs, tool.Slug)
	}
	opts.Allowlist = testAllowlist()
	opts.IPPolicy = NewLoopbackUpstreamPolicyForTests()
	if opts.Timeout == 0 {
		opts.Timeout = time.Second
	}
	checker := NewHealthChecker(targets, repo, activity, opts)
	return checker
}

func TestHealthCheckActiveToolRecordsHealthy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("unexpected probe path %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	repo := &fakeHealthRepo{}
	checker := newHealthCheckerForTest(t, []*model.Tool{healthTool(1, "image-compressor", upstream.URL)}, repo, nil, HealthCheckOptions{})
	checker.client = upstream.Client()

	if err := checker.Probe(context.Background(), "image-compressor"); err != nil {
		t.Fatalf("probe: %v", err)
	}
	rows := repo.rowsSnapshot()
	if len(rows) != 1 {
		t.Fatalf("expected 1 check row, got %d", len(rows))
	}
	if rows[0].Status != model.HealthStatusHealthy {
		t.Fatalf("expected healthy, got %q", rows[0].Status)
	}
	if rows[0].HTTPStatusCode == nil || *rows[0].HTTPStatusCode != 200 {
		t.Fatal("http status code not recorded")
	}
	if rows[0].LatencyMS == nil {
		t.Fatal("latency not recorded")
	}
	if rows[0].CheckedAt.IsZero() {
		t.Fatal("checked_at must be set")
	}
	if rows[0].ErrorMessage != nil {
		t.Fatalf("healthy check must not carry an error: %v", *rows[0].ErrorMessage)
	}
}

func TestHealthCheckUnhealthyOnServerError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer upstream.Close()

	repo := &fakeHealthRepo{}
	checker := newHealthCheckerForTest(t, []*model.Tool{healthTool(1, "tool-a", upstream.URL)}, repo, nil, HealthCheckOptions{})
	checker.client = upstream.Client()

	if err := checker.Probe(context.Background(), "tool-a"); err != nil {
		t.Fatalf("probe: %v", err)
	}
	row := repo.rowsSnapshot()[0]
	if row.Status != model.HealthStatusUnhealthy {
		t.Fatalf("expected unhealthy, got %q", row.Status)
	}
	if row.ErrorMessage == nil || !strings.Contains(*row.ErrorMessage, "unexpected status code") {
		t.Fatalf("unexpected reason: %v", row.ErrorMessage)
	}
}

func TestHealthCheckTimeoutIsUnhealthy(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-release
	}))
	defer func() {
		close(release)
		upstream.Close()
	}()

	repo := &fakeHealthRepo{}
	checker := newHealthCheckerForTest(t, []*model.Tool{healthTool(1, "slow-tool", upstream.URL)}, repo, nil, HealthCheckOptions{Timeout: 100 * time.Millisecond})
	checker.client = upstream.Client()
	checker.client.Timeout = 100 * time.Millisecond

	if err := checker.Probe(context.Background(), "slow-tool"); err != nil {
		t.Fatalf("probe: %v", err)
	}
	row := repo.rowsSnapshot()[0]
	if row.Status != model.HealthStatusUnhealthy {
		t.Fatalf("expected unhealthy, got %q", row.Status)
	}
	if row.ErrorMessage == nil || *row.ErrorMessage != HealthReasonTimeout {
		t.Fatalf("expected timeout reason, got %v", row.ErrorMessage)
	}
}

func TestHealthCheckConnectionFailureIsUnhealthy(t *testing.T) {
	// Bind and immediately close to get a refused port.
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	badURL := upstream.URL
	upstream.Close()

	repo := &fakeHealthRepo{}
	checker := newHealthCheckerForTest(t, []*model.Tool{healthTool(1, "dead-tool", badURL)}, repo, nil, HealthCheckOptions{Timeout: 500 * time.Millisecond})
	checker.client = &http.Client{Timeout: 500 * time.Millisecond}

	if err := checker.Probe(context.Background(), "dead-tool"); err != nil {
		t.Fatalf("probe: %v", err)
	}
	row := repo.rowsSnapshot()[0]
	if row.Status != model.HealthStatusUnhealthy {
		t.Fatalf("expected unhealthy, got %q", row.Status)
	}
	if row.ErrorMessage == nil {
		t.Fatal("expected a reason")
	}
	if *row.ErrorMessage != HealthReasonConnectionFailed && *row.ErrorMessage != HealthReasonTimeout {
		t.Fatalf("reason must be a fixed code, got %q", *row.ErrorMessage)
	}
}

func TestHealthCheckSkipsNonActiveTools(t *testing.T) {
	for _, status := range []string{model.ToolStatusDraft, model.ToolStatusMaintenance, model.ToolStatusDisabled} {
		status := status
		t.Run(status, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("non-active tool must not be probed")
			}))
			defer upstream.Close()

			tool := healthTool(1, "inactive-tool", upstream.URL)
			tool.Status = status
			repo := &fakeHealthRepo{}
			checker := newHealthCheckerForTest(t, []*model.Tool{tool}, repo, nil, HealthCheckOptions{})
			checker.client = upstream.Client()

			if err := checker.Probe(context.Background(), "inactive-tool"); !errors.Is(err, ErrToolNotFound) {
				t.Fatalf("expected ErrToolNotFound, got %v", err)
			}
			if n := atomic.LoadInt32(&repo.insert); n != 0 {
				t.Fatalf("expected no stored checks, got %d", n)
			}
		})
	}
}

func TestHealthCheckSkipsDeletedTools(t *testing.T) {
	now := time.Now()
	tool := healthTool(1, "deleted-tool", "http://deleted-tool:8000")
	tool.DeletedAt = &now
	repo := &fakeHealthRepo{}
	checker := newHealthCheckerForTest(t, []*model.Tool{tool}, repo, nil, HealthCheckOptions{})

	if err := checker.Probe(context.Background(), "deleted-tool"); !errors.Is(err, ErrToolNotFound) {
		t.Fatalf("expected ErrToolNotFound, got %v", err)
	}
}

func TestHealthCheckRecordsRecoveryTransition(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	repo := &fakeHealthRepo{prev: map[uint64]string{1: model.HealthStatusUnhealthy}}
	activityRepo := &fakeActivityRepo{}
	activity := newActivityService(activityRepo, 0)
	checker := newHealthCheckerForTest(t, []*model.Tool{healthTool(1, "tool-a", upstream.URL)}, repo, activity, HealthCheckOptions{})
	checker.client = upstream.Client()

	if err := checker.Probe(context.Background(), "tool-a"); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if len(activityRepo.rows) != 1 {
		t.Fatalf("expected 1 activity row, got %d", len(activityRepo.rows))
	}
	if activityRepo.rows[0].Action != ActionHealthCheckRecovered {
		t.Fatalf("expected recovery action, got %q", activityRepo.rows[0].Action)
	}
	if activityRepo.rows[0].ActorType != model.ActorTypeSystem {
		t.Fatal("health transitions must be recorded as system activity")
	}
}

func TestHealthCheckRecordsFailureTransition(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer upstream.Close()

	repo := &fakeHealthRepo{prev: map[uint64]string{1: model.HealthStatusHealthy}}
	activityRepo := &fakeActivityRepo{}
	activity := newActivityService(activityRepo, 0)
	checker := newHealthCheckerForTest(t, []*model.Tool{healthTool(1, "tool-a", upstream.URL)}, repo, activity, HealthCheckOptions{})
	checker.client = upstream.Client()

	if err := checker.Probe(context.Background(), "tool-a"); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if len(activityRepo.rows) != 1 {
		t.Fatalf("expected 1 activity row, got %d", len(activityRepo.rows))
	}
	if activityRepo.rows[0].Action != ActionHealthCheckFailed {
		t.Fatalf("expected failure action, got %q", activityRepo.rows[0].Action)
	}
}

func TestHealthCheckDoesNotLogSteadyState(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	repo := &fakeHealthRepo{prev: map[uint64]string{1: model.HealthStatusHealthy}}
	activityRepo := &fakeActivityRepo{}
	activity := newActivityService(activityRepo, 0)
	checker := newHealthCheckerForTest(t, []*model.Tool{healthTool(1, "tool-a", upstream.URL)}, repo, activity, HealthCheckOptions{})
	checker.client = upstream.Client()

	if err := checker.Probe(context.Background(), "tool-a"); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if len(activityRepo.rows) != 0 {
		t.Fatalf("steady state must not spam the audit log, got %d rows", len(activityRepo.rows))
	}
}

func TestHealthCheckFirstHealthyResultIsNotARecovery(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	repo := &fakeHealthRepo{}
	activityRepo := &fakeActivityRepo{}
	activity := newActivityService(activityRepo, 0)
	checker := newHealthCheckerForTest(t, []*model.Tool{healthTool(1, "tool-a", upstream.URL)}, repo, activity, HealthCheckOptions{})
	checker.client = upstream.Client()

	_ = checker.Probe(context.Background(), "tool-a")
	if len(activityRepo.rows) != 0 {
		t.Fatalf("first healthy check is not a recovery, got %d rows", len(activityRepo.rows))
	}
}

func TestHealthCheckConcurrentProbesAreBounded(t *testing.T) {
	var current, peak int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&current, 1)
		for {
			old := atomic.LoadInt32(&peak)
			if n <= old || atomic.CompareAndSwapInt32(&peak, old, n) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
		atomic.AddInt32(&current, -1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	var tools []*model.Tool
	for i := 1; i <= 8; i++ {
		tools = append(tools, healthTool(uint64(i), "tool-"+string(rune('a'+i-1)), upstream.URL))
	}
	repo := &fakeHealthRepo{}
	checker := newHealthCheckerForTest(t, tools, repo, nil, HealthCheckOptions{MaxConcurrent: 3})
	checker.client = upstream.Client()

	if _, err := checker.Sweep(context.Background()); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if atomic.LoadInt32(&peak) > 3 {
		t.Fatalf("concurrency exceeded the pool: peak=%d", peak)
	}
	if len(repo.rowsSnapshot()) != 8 {
		t.Fatalf("expected 8 checks, got %d", len(repo.rowsSnapshot()))
	}
}

func TestHealthCheckDoesNotDuplicateInFlightProbe(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer func() {
		releaseAll()
		upstream.Close()
	}()

	repo := &fakeHealthRepo{}
	checker := newHealthCheckerForTest(t, []*model.Tool{healthTool(1, "tool-a", upstream.URL)}, repo, nil, HealthCheckOptions{Timeout: 5 * time.Second})
	checker.client = upstream.Client()

	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		done <- checker.Probe(context.Background(), "tool-a")
	}()
	<-started
	time.Sleep(50 * time.Millisecond)

	if err := checker.Probe(context.Background(), "tool-a"); !errors.Is(err, ErrHealthCheckInFlight) {
		t.Fatalf("expected ErrHealthCheckInFlight, got %v", err)
	}
	releaseAll()
	if err := <-done; err != nil {
		t.Fatalf("first probe failed: %v", err)
	}
	if n := len(repo.rowsSnapshot()); n != 1 {
		t.Fatalf("duplicate check stored: %d rows", n)
	}
}

func TestHealthCheckRejectsNonAllowlistedHostWithoutProbing(t *testing.T) {
	var calls int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		atomic.AddInt32(&calls, 1)
	}))
	defer upstream.Close()

	repo := &fakeHealthRepo{}
	tool := healthTool(1, "evil-tool", upstream.URL)
	checker := newHealthCheckerForTest(t, []*model.Tool{tool}, repo, nil, HealthCheckOptions{Timeout: 500 * time.Millisecond})

	// Loopback is permitted by the test policy but the hostname "127.0.0.1" is
	// not in the allowlist, and an IP literal bypasses it only for allowlisted
	// policies. Use a policy that denies loopback to prove the guard.
	checker = NewHealthChecker(
		&fakeHealthTargets{tools: map[string]*model.Tool{tool.Slug: tool}, slugs: []string{tool.Slug}},
		repo, nil,
		HealthCheckOptions{Timeout: 500 * time.Millisecond, Allowlist: NewUpstreamAllowlist(), IPPolicy: DefaultUpstreamIPPolicy()},
	)

	_ = checker.Probe(context.Background(), "evil-tool")
	if n := atomic.LoadInt32(&calls); n != 0 {
		t.Fatalf("denied upstream was contacted %d times", n)
	}
	rows := repo.rowsSnapshot()
	if len(rows) != 1 || rows[0].Status != model.HealthStatusUnhealthy {
		t.Fatalf("expected one unhealthy row, got %+v", rows)
	}
	if rows[0].ErrorMessage == nil || *rows[0].ErrorMessage != HealthReasonUpstreamRejected {
		t.Fatalf("expected upstream rejected reason, got %v", rows[0].ErrorMessage)
	}
}

func TestHealthCheckErrorReasonNeverLeaksAddress(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	badURL := upstream.URL
	upstream.Close()

	repo := &fakeHealthRepo{}
	checker := newHealthCheckerForTest(t, []*model.Tool{healthTool(1, "dead-tool", badURL)}, repo, nil, HealthCheckOptions{Timeout: 500 * time.Millisecond})
	checker.client = &http.Client{Timeout: 500 * time.Millisecond}

	_ = checker.Probe(context.Background(), "dead-tool")
	row := repo.rowsSnapshot()[0]
	if row.ErrorMessage == nil {
		t.Fatal("expected reason")
	}
	if strings.Contains(*row.ErrorMessage, "127.0.0.1") || strings.Contains(*row.ErrorMessage, ":") {
		t.Fatalf("reason leaked connection details: %q", *row.ErrorMessage)
	}
}

func TestHealthProbePathCannotEscapeOrigin(t *testing.T) {
	tool := healthTool(1, "escape-tool", "http://escape-tool:8000")
	tool.HealthcheckPath = "/../../admin"

	repo := &fakeHealthRepo{}
	checker := newHealthCheckerForTest(t, []*model.Tool{tool}, repo, nil, HealthCheckOptions{})
	_ = checker.Probe(context.Background(), "escape-tool")

	row := repo.rowsSnapshot()[0]
	if row.Status != model.HealthStatusUnhealthy {
		t.Fatalf("expected unhealthy, got %q", row.Status)
	}
	if row.ErrorMessage == nil || *row.ErrorMessage != HealthReasonUpstreamRejected {
		t.Fatalf("expected rejected reason, got %v", row.ErrorMessage)
	}
}

func TestHealthCheckSweepSkipsWhenNoActiveTools(t *testing.T) {
	repo := &fakeHealthRepo{}
	checker := NewHealthChecker(&fakeHealthTargets{tools: map[string]*model.Tool{}}, repo, nil, HealthCheckOptions{})
	n, err := checker.Sweep(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 checks, got %d", n)
	}
}

func TestHealthCheckDefaultsAreConservative(t *testing.T) {
	checker := NewHealthChecker(&fakeHealthTargets{}, &fakeHealthRepo{}, nil, HealthCheckOptions{})
	if checker.Interval() != DefaultHealthInterval {
		t.Fatalf("expected default interval, got %s", checker.Interval())
	}
	if cap(checker.slots) != DefaultHealthMaxConcurrent {
		t.Fatalf("expected default pool size, got %d", cap(checker.slots))
	}
}
