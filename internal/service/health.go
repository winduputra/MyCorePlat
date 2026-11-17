package service

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/winduputra/MyCorePlat/internal/model"
)

// Health check defaults. All are conservative because the poller talks to
// every active tool on a fixed cadence (docs/architecture.md Ãƒâ€šÃ‚Â§4.6).
const (
	DefaultHealthInterval      = 30 * time.Second
	DefaultHealthTimeout       = 5 * time.Second
	DefaultHealthMaxConcurrent = 5
)

// Reason codes stored in tool_health_checks.error_message. They are fixed
// strings on purpose: a raw transport error could echo internal hostnames,
// IP addresses or connection details into the audit trail.
const (
	HealthReasonTimeout                = "timeout"
	HealthReasonConnectionFailed       = "connection failed"
	HealthReasonTLSFailed              = "tls handshake failed"
	HealthReasonUpstreamRejected       = "upstream address not allowed"
	HealthReasonStatusUnexpected       = "unexpected status code"
	HealthReasonBodyTooLarge           = "response body too large"
	HealthReasonRequestFailed          = "request failed"
	maxHealthReasonLen                 = 512
	maxHealthProbeBodyBytes      int64 = 4 << 10
)

// HealthTargetRepository supplies the tools the poller may probe.
type HealthTargetRepository interface {
	// ListActiveSlugs returns the slugs of active, non-deleted tools.
	ListActiveSlugs(ctx context.Context) ([]string, error)
	// GetForHealth returns one tool by slug, or ErrToolNotFound.
	GetForHealth(ctx context.Context, slug string) (*model.Tool, error)
}

// ToolHealthRepository persists probe results.
type ToolHealthRepository interface {
	Insert(ctx context.Context, check *model.ToolHealthCheck) error
	LatestByTool(ctx context.Context, toolIDs []uint64) (map[uint64]*model.ToolHealthCheck, error)
	ListByTool(ctx context.Context, toolID uint64, limit int) ([]model.ToolHealthCheck, error)
	PreviousStatus(ctx context.Context, toolID uint64) (string, error)
}

// HealthCheckOptions configures the poller.
type HealthCheckOptions struct {
	Interval      time.Duration
	Timeout       time.Duration
	MaxConcurrent int
	// Allowlist and IPPolicy are the Task 9 SSRF controls. Health probes go
	// through the same pinned transport as proxied traffic, so a probe can
	// never reach a destination the gateway itself would refuse.
	Allowlist UpstreamAllowlist
	IPPolicy  UpstreamIPPolicy
	Resolver  IPResolver
	// TLSRootCAs overrides the probe client's roots (internal CAs, tests).
	TLSRootCAs *tls.Config
	// Transport overrides the probe transport entirely. Production leaves this
	// nil so the pinned, policy-enforcing transport is used.
	Transport http.RoundTripper
}

// HealthChecker probes tool health endpoints and records the outcome.
type HealthChecker struct {
	targets  HealthTargetRepository
	health   ToolHealthRepository
	activity *ActivityService
	client   *http.Client
	interval time.Duration
	timeout  time.Duration
	slots    chan struct{}
	// inflight guarantees at most one running probe per tool, even if a caller
	// invokes Probe directly while a sweep is running.
	inflight sync.Map
	now      func() time.Time
}

// NewHealthChecker builds a poller with a bounded concurrency pool.
func NewHealthChecker(targets HealthTargetRepository, health ToolHealthRepository, activity *ActivityService, opts HealthCheckOptions) *HealthChecker {
	if opts.Interval <= 0 {
		opts.Interval = DefaultHealthInterval
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultHealthTimeout
	}
	if opts.MaxConcurrent <= 0 {
		opts.MaxConcurrent = DefaultHealthMaxConcurrent
	}
	if opts.Resolver == nil {
		opts.Resolver = SystemResolver()
	}
	if !opts.IPPolicy.IsConfigured() {
		opts.IPPolicy = DefaultUpstreamIPPolicy()
	}

	transport := opts.Transport
	if transport == nil {
		dialer := &healthPinnedDialer{
			resolver: opts.Resolver,
			policy:   opts.IPPolicy,
			allow:    opts.Allowlist,
			dialer:   &net.Dialer{Timeout: opts.Timeout, KeepAlive: 30 * time.Second},
		}
		transport = &http.Transport{
			Proxy:                 nil,
			DialContext:           dialer.DialContext,
			TLSClientConfig:       opts.TLSRootCAs,
			ForceAttemptHTTP2:     false,
			MaxIdleConns:          opts.MaxConcurrent * 2,
			MaxIdleConnsPerHost:   2,
			IdleConnTimeout:       60 * time.Second,
			TLSHandshakeTimeout:   opts.Timeout,
			ResponseHeaderTimeout: opts.Timeout,
			DisableCompression:    true,
			DisableKeepAlives:     false,
		}
	}

	return &HealthChecker{
		targets:  targets,
		health:   health,
		activity: activity,
		client: &http.Client{
			Transport: transport,
			Timeout:   opts.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				// A redirect is never followed: the target would not have been
				// validated by the SSRF policy.
				return http.ErrUseLastResponse
			},
		},
		interval: opts.Interval,
		timeout:  opts.Timeout,
		slots:    make(chan struct{}, opts.MaxConcurrent),
		now:      time.Now,
	}
}

// Interval exposes the configured sweep cadence.
func (h *HealthChecker) Interval() time.Duration { return h.interval }

// Run sweeps until the context is cancelled. Sweeps never overlap: the next
// tick is only scheduled after the previous sweep finished.
func (h *HealthChecker) Run(ctx context.Context) {
	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()

	// Probe once immediately so the dashboard is not empty for a full interval.
	_, _ = h.Sweep(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = h.Sweep(ctx)
		}
	}
}

// Sweep probes every active tool once and returns the number of completed
// checks. Tools already being probed are skipped, which is what keeps a slow
// tool from being checked twice.
func (h *HealthChecker) Sweep(ctx context.Context) (int, error) {
	if h == nil || h.targets == nil {
		return 0, nil
	}
	slugs, err := h.targets.ListActiveSlugs(ctx)
	if err != nil {
		return 0, err
	}
	if len(slugs) == 0 {
		return 0, nil
	}

	var wg sync.WaitGroup
	completed := make(chan struct{}, len(slugs))
	for _, slug := range slugs {
		slug := slug
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case h.slots <- struct{}{}:
				defer func() { <-h.slots }()
			case <-ctx.Done():
				return
			}
			if err := h.Probe(ctx, slug); err == nil {
				completed <- struct{}{}
			}
		}()
	}
	wg.Wait()
	close(completed)

	count := 0
	for range completed {
		count++
	}
	return count, nil
}

// ErrHealthCheckInFlight is returned when the same tool is already being
// probed; callers treat it as a no-op.
var ErrHealthCheckInFlight = errors.New("health check already in flight")

// Probe checks one tool and stores the result. Only active tools are probed.
func (h *HealthChecker) Probe(ctx context.Context, slug string) error {
	if h == nil || h.targets == nil || h.health == nil {
		return ErrToolNotFound
	}
	if _, loaded := h.inflight.LoadOrStore(slug, struct{}{}); loaded {
		return ErrHealthCheckInFlight
	}
	defer h.inflight.Delete(slug)

	tool, err := h.targets.GetForHealth(ctx, slug)
	if err != nil {
		return err
	}
	if tool == nil || tool.Status != model.ToolStatusActive || tool.DeletedAt != nil {
		// Draft/maintenance/disabled/removed tools are never probed: probing a
		// disabled tool would generate traffic to a service an admin turned off.
		return ErrToolNotFound
	}

	check := h.probe(ctx, tool)

	previous, err := h.health.PreviousStatus(ctx, tool.ID)
	if err != nil {
		previous = ""
	}
	if err := h.health.Insert(ctx, check); err != nil {
		return err
	}

	h.recordTransition(ctx, tool, previous, check)
	return nil
}

// probe performs one HTTP probe and converts the outcome into a health row.
func (h *HealthChecker) probe(ctx context.Context, tool *model.Tool) *model.ToolHealthCheck {
	check := &model.ToolHealthCheck{
		ToolID:    tool.ID,
		Status:    model.HealthStatusUnhealthy,
		CheckedAt: h.now().UTC(),
	}

	target, err := healthTargetURL(tool)
	if err != nil {
		check.ErrorMessage = nilIfEmpty(HealthReasonUpstreamRejected)
		return check
	}

	probeCtx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, target, nil)
	if err != nil {
		check.ErrorMessage = nilIfEmpty(HealthReasonRequestFailed)
		return check
	}
	req.Header.Set("User-Agent", "tools-bpbj-healthcheck/1")
	req.Header.Set("Accept", "*/*")

	start := time.Now()
	resp, err := h.client.Do(req)
	elapsed := time.Since(start)
	latency := int(elapsed.Milliseconds())
	check.LatencyMS = &latency

	if err != nil {
		check.ErrorMessage = nilIfEmpty(classifyHealthError(err))
		return check
	}
	defer func() { _ = resp.Body.Close() }()
	// Drain a bounded amount so the connection can be reused, but never buffer
	// an unbounded response body.
	_, _ = readAtMost(resp.Body, maxHealthProbeBodyBytes)

	code := resp.StatusCode
	check.HTTPStatusCode = &code
	if code >= 200 && code < 300 {
		check.Status = model.HealthStatusHealthy
		return check
	}
	check.ErrorMessage = nilIfEmpty(fmt.Sprintf("%s (%d)", HealthReasonStatusUnexpected, code))
	return check
}

// recordTransition writes an activity entry when a tool flips state.
func (h *HealthChecker) recordTransition(ctx context.Context, tool *model.Tool, previous string, check *model.ToolHealthCheck) {
	if h.activity == nil {
		return
	}
	if previous == check.Status {
		return
	}
	// A first-ever result is not a recovery: there was no prior state to
	// recover from.
	if previous == "" && check.Status == model.HealthStatusHealthy {
		return
	}

	action := ActionHealthCheckFailed
	if check.Status == model.HealthStatusHealthy {
		action = ActionHealthCheckRecovered
	}
	toolID := tool.ID
	metadata := map[string]any{
		"slug":        tool.Slug,
		"status":      check.Status,
		"previous":    previous,
		"latency_ms":  latencyValue(check),
		"status_code": statusCodeValue(check),
		"reason":      reasonValue(check),
	}
	if previous == "" {
		metadata["previous"] = "unknown"
	}

	h.activity.Record(ctx, ActivityEntry{
		ActorType:  model.ActorTypeSystem,
		Action:     action,
		EntityType: EntityTypeTool,
		EntityID:   &toolID,
		ToolID:     &toolID,
		Metadata:   metadata,
	})
}

func latencyValue(check *model.ToolHealthCheck) any {
	if check.LatencyMS == nil {
		return nil
	}
	return *check.LatencyMS
}

func statusCodeValue(check *model.ToolHealthCheck) any {
	if check.HTTPStatusCode == nil {
		return nil
	}
	return *check.HTTPStatusCode
}

func reasonValue(check *model.ToolHealthCheck) any {
	if check.ErrorMessage == nil {
		return nil
	}
	return *check.ErrorMessage
}

// healthTargetURL builds the probe URL from the tool's upstream and the fixed
// healthcheck path. Both are re-validated so a stale row cannot slip through.
func healthTargetURL(tool *model.Tool) (string, error) {
	if tool == nil {
		return "", ErrToolNotFound
	}
	path := strings.TrimSpace(tool.HealthcheckPath)
	if path == "" {
		path = "/health"
	}
	if !strings.HasPrefix(path, "/") {
		return "", ErrInvalidUpstream
	}
	base, err := url.Parse(strings.TrimSpace(tool.UpstreamURL))
	if err != nil {
		return "", ErrInvalidUpstream
	}
	if base.Scheme == "" || base.Host == "" {
		return "", ErrInvalidUpstream
	}
	// A health path must not be able to escape the tool's own origin.
	if strings.Contains(path, "..") {
		return "", ErrInvalidUpstream
	}
	probe := *base
	probe.Path = strings.TrimSuffix(base.Path, "/") + path
	probe.RawQuery = ""
	probe.Fragment = ""
	return probe.String(), nil
}

// classifyHealthError maps a transport error onto a fixed reason code. The
// original error text is discarded because it can embed hostnames and IPs.
func classifyHealthError(err error) string {
	if err == nil {
		return ""
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return HealthReasonTimeout
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return HealthReasonTimeout
	}
	var tlsErr *tls.CertificateVerificationError
	if errors.As(err, &tlsErr) {
		return HealthReasonTLSFailed
	}
	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) {
		return HealthReasonTLSFailed
	}
	if errors.Is(err, ErrUpstreamAddressNotAllowed) || errors.Is(err, ErrUpstreamResolveFailed) || errors.Is(err, ErrInvalidUpstream) {
		return HealthReasonUpstreamRejected
	}
	if errors.Is(err, context.Canceled) {
		return HealthReasonRequestFailed
	}
	return HealthReasonConnectionFailed
}

// readAtMost reads up to limit bytes and discards the rest of the stream
// without buffering it.
func readAtMost(body io.Reader, limit int64) (int64, error) {
	written, err := io.CopyN(io.Discard, body, limit)
	if errors.Is(err, io.EOF) {
		return written, nil
	}
	return written, err
}
