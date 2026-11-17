package gateway_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/winduputra/MyCorePlat/internal/gateway"
	"github.com/winduputra/MyCorePlat/internal/model"
	"github.com/winduputra/MyCorePlat/internal/service"
)

// ---------------------------------------------------------------- test doubles

type fakeToolLookup struct {
	tools map[string]*model.Tool
	err   error
	calls int
}

func (f *fakeToolLookup) GetBySlug(_ context.Context, slug string) (*model.Tool, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	tool, ok := f.tools[slug]
	if !ok {
		return nil, service.ErrToolNotFound
	}
	return tool, nil
}

func newLookup(tools ...*model.Tool) *fakeToolLookup {
	bySlug := make(map[string]*model.Tool, len(tools))
	for _, t := range tools {
		bySlug[t.Slug] = t
	}
	return &fakeToolLookup{tools: bySlug}
}

func activeTool(slug, upstream string) *model.Tool {
	return &model.Tool{
		ID:              1,
		Slug:            slug,
		Name:            slug,
		AccessType:      model.ToolAccessPublic,
		UpstreamURL:     upstream,
		HealthcheckPath: "/health",
		Status:          model.ToolStatusActive,
	}
}

// permissiveValidator is used by most tests because httptest upstreams listen on
// 127.0.0.1 with a random port, which the production SSRF allowlist (correctly)
// rejects. Tests that assert SSRF behaviour inject the real validator.
func permissiveValidator(string) error { return nil }

func newGatewayRouter(t *testing.T, lookup gateway.ToolLookup, opts gateway.Options) *gin.Engine {
	t.Helper()
	if opts.UpstreamValidator == nil {
		opts.UpstreamValidator = permissiveValidator
	}
	if !opts.IPPolicy.IsConfigured() {
		// httptest upstreams listen on 127.0.0.1, which the production policy
		// denies on purpose. Every test therefore opts into the loopback policy
		// unless it exercises the address policy itself.
		opts.IPPolicy = service.NewLoopbackUpstreamPolicyForTests()
	}
	gin.SetMode(gin.TestMode)
	g := gateway.New(lookup, opts)
	r := gin.New()
	r.Any("/t/:slug", g.Serve)
	r.Any("/t/:slug/*path", g.Serve)
	return r
}

func doRequest(t *testing.T, h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// ---------------------------------------------------------------- basic proxy

func TestActivePublicToolIsProxied(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello from tool"))
	}))
	defer upstream.Close()

	router := newGatewayRouter(t, newLookup(activeTool("echo-tool", upstream.URL)), gateway.Options{})

	rec := doRequest(t, router, httptest.NewRequest(http.MethodGet, "/t/echo-tool/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%q)", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != "hello from tool" {
		t.Errorf("body = %q, want %q", got, "hello from tool")
	}
}

func TestToolNotFoundReturns404(t *testing.T) {
	router := newGatewayRouter(t, newLookup(), gateway.Options{})

	rec := doRequest(t, router, httptest.NewRequest(http.MethodGet, "/t/missing-tool/", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestLookupErrorReturns500WithoutLeakingDetail(t *testing.T) {
	lookup := newLookup()
	lookup.err = errors.New("driver: connection string server=db user=secret")

	router := newGatewayRouter(t, lookup, gateway.Options{})
	rec := doRequest(t, router, httptest.NewRequest(http.MethodGet, "/t/any-tool/", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "connection string") || strings.Contains(rec.Body.String(), "secret") {
		t.Errorf("response leaked internal detail: %q", rec.Body.String())
	}
}

func TestDisabledToolRejected(t *testing.T) {
	tool := activeTool("disabled-tool", "http://127.0.0.1:1")
	tool.Status = model.ToolStatusDisabled

	router := newGatewayRouter(t, newLookup(tool), gateway.Options{})
	rec := doRequest(t, router, httptest.NewRequest(http.MethodGet, "/t/disabled-tool/", nil))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestDraftToolReturns404(t *testing.T) {
	tool := activeTool("draft-tool", "http://127.0.0.1:1")
	tool.Status = model.ToolStatusDraft

	router := newGatewayRouter(t, newLookup(tool), gateway.Options{})
	rec := doRequest(t, router, httptest.NewRequest(http.MethodGet, "/t/draft-tool/", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestMaintenanceToolReturns503WithNotice(t *testing.T) {
	tool := activeTool("maint-tool", "http://127.0.0.1:1")
	tool.Status = model.ToolStatusMaintenance
	notice := "Sedang diperbaiki, coba lagi nanti."
	tool.MaintenanceMessage = &notice

	router := newGatewayRouter(t, newLookup(tool), gateway.Options{})
	rec := doRequest(t, router, httptest.NewRequest(http.MethodGet, "/t/maint-tool/", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), notice) {
		t.Errorf("body = %q, want to contain maintenance notice", rec.Body.String())
	}
}

func TestSoftDeletedToolReturns404(t *testing.T) {
	// A soft-deleted tool is invisible to the repository, which reports
	// ErrToolNotFound. The gateway must surface that as 404, never proxy it.
	tool := activeTool("deleted-tool", "http://127.0.0.1:1")
	router := newGatewayRouter(t, newLookup(tool), gateway.Options{})

	rec := doRequest(t, router, httptest.NewRequest(http.MethodGet, "/t/gone-tool/", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestTokenAccessRejectedWithoutValidator(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream must not be contacted when no token validator is configured")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	tool := activeTool("token-tool", upstream.URL)
	tool.AccessType = model.ToolAccessToken

	router := newGatewayRouter(t, newLookup(tool), gateway.Options{})
	rec := doRequest(t, router, httptest.NewRequest(http.MethodGet, "/t/token-tool/", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// ---------------------------------------------- request/response pass-through

func TestMethodPathQueryAndBodyForwarded(t *testing.T) {
	type captured struct {
		method string
		path   string
		query  string
		body   string
	}
	got := make(chan captured, 1)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- captured{method: r.Method, path: r.URL.Path, query: r.URL.RawQuery, body: string(body)}
		w.WriteHeader(http.StatusCreated)
	}))
	defer upstream.Close()

	tool := activeTool("multi-tool", upstream.URL+"/base")
	router := newGatewayRouter(t, newLookup(tool), gateway.Options{})

	req := httptest.NewRequest(http.MethodPut, "/t/multi-tool/a/b?x=1&y=two", strings.NewReader("payload"))
	rec := doRequest(t, router, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rec.Code)
	}
	select {
	case c := <-got:
		if c.method != http.MethodPut {
			t.Errorf("method = %q, want PUT", c.method)
		}
		if c.path != "/base/a/b" {
			t.Errorf("path = %q, want /base/a/b", c.path)
		}
		if c.query != "x=1&y=two" {
			t.Errorf("query = %q, want x=1&y=two", c.query)
		}
		if c.body != "payload" {
			t.Errorf("body = %q, want payload", c.body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("upstream did not receive the request")
	}
}

func TestResponseStatusBodyAndHeadersForwarded(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Tool-Custom", "custom-value")
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte(`{"ok":false}`))
	}))
	defer upstream.Close()

	router := newGatewayRouter(t, newLookup(activeTool("teapot-tool", upstream.URL)), gateway.Options{})
	rec := doRequest(t, router, httptest.NewRequest(http.MethodGet, "/t/teapot-tool/", nil))

	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want 418", rec.Code)
	}
	if got := rec.Body.String(); got != `{"ok":false}` {
		t.Errorf("body = %q", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if got := rec.Header().Get("X-Tool-Custom"); got != "custom-value" {
		t.Errorf("X-Tool-Custom = %q, want custom-value", got)
	}
}

func TestHopByHopHeadersRemoved(t *testing.T) {
	seen := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		w.Header().Set("Connection", "close")
		w.Header().Set("Keep-Alive", "timeout=5")
		w.Header().Set("X-Response-Keep", "keep-me")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	router := newGatewayRouter(t, newLookup(activeTool("hop-tool", upstream.URL)), gateway.Options{})
	req := httptest.NewRequest(http.MethodGet, "/t/hop-tool/", nil)
	req.Header.Set("Connection", "X-Request-Hop")
	req.Header.Set("X-Request-Hop", "drop-me")
	req.Header.Set("Keep-Alive", "timeout=5")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("X-Request-Keep", "keep-me")

	rec := doRequest(t, router, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	h := <-seen
	for _, name := range []string{"X-Request-Hop", "Keep-Alive", "Upgrade"} {
		if v := h.Get(name); v != "" {
			t.Errorf("hop-by-hop request header %s forwarded as %q", name, v)
		}
	}
	if v := h.Get("X-Request-Keep"); v != "keep-me" {
		t.Errorf("X-Request-Keep = %q, want keep-me", v)
	}
	for _, name := range []string{"Keep-Alive", "X-Connection-Hop"} {
		if v := rec.Header().Get(name); v != "" {
			t.Errorf("hop-by-hop response header leaked: %s=%q", name, v)
		}
	}
	if v := rec.Header().Get("Connection"); v != "" && v != "close" {
		t.Errorf("response Connection = %q, want empty or close", v)
	}
	if v := rec.Header().Get("X-Response-Keep"); v != "keep-me" {
		t.Errorf("X-Response-Keep = %q, want keep-me", v)
	}
}

func TestAdminCookieAndClientAuthHeadersStripped(t *testing.T) {
	seen := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	router := newGatewayRouter(t, newLookup(activeTool("strip-tool", upstream.URL)), gateway.Options{})
	req := httptest.NewRequest(http.MethodGet, "/t/strip-tool/", nil)
	req.Header.Set("Cookie", "bpbj_admin_session=super-secret-session; other=1")
	req.Header.Set("Authorization", "Bearer stolen-token")
	req.Header.Set("Proxy-Authorization", "Basic abc")
	req.Header.Set("X-Signature", "forged-signature")
	req.Header.Set("X-Signature-Key-Id", "k1")
	req.Header.Set("X-Signature-Timestamp", "123")
	req.Header.Set("X-Signature-Nonce", "abc")
	req.Header.Set("X-Gateway", "evil-gateway")
	req.Header.Set("X-Tool-Slug", "evil-slug")
	req.Header.Set("X-Access-Type", "token")
	req.Header.Set("X-Admin-Id", "1")
	req.Header.Set("X-User-Role", "superadmin")
	req.Header.Set("X-Forwarded-For", "10.9.9.9")

	rec := doRequest(t, router, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	h := <-seen
	// X-Tool-Slug / X-Access-Type are present because *Core* sets them; the
	// client's forged values must not survive. They are asserted below.
	stripped := []string{
		"Cookie", "Authorization", "Proxy-Authorization",
		"X-Signature", "X-Signature-Key-Id", "X-Signature-Timestamp", "X-Signature-Nonce",
		"X-Admin-Id", "X-User-Role",
	}
	for _, name := range stripped {
		if v := h.Get(name); v != "" {
			t.Errorf("client header %s must be stripped, got %q", name, v)
		}
	}

	// Core owns these: it must set its own identity, not echo the client's.
	if v := h.Get("X-Gateway"); v != "tools-bpbj-core" {
		t.Errorf("X-Gateway = %q, want tools-bpbj-core", v)
	}
	if v := h.Get("X-Tool-Slug"); v != "strip-tool" {
		t.Errorf("X-Tool-Slug = %q, want strip-tool", v)
	}
	if v := h.Get("X-Access-Type"); v != "public" {
		t.Errorf("X-Access-Type = %q, want public", v)
	}
	if v := h.Get("X-Forwarded-For"); strings.Contains(v, "10.9.9.9") {
		t.Errorf("client-supplied X-Forwarded-For was trusted: %q", v)
	}
	if v := h.Get("X-Forwarded-For"); v == "" {
		t.Error("X-Forwarded-For should be injected by Core")
	}
	// Internal signature headers are Task 8; they must not appear yet.
	if v := h.Get("X-Signature"); v != "" {
		t.Errorf("X-Signature must not be added before Task 8, got %q", v)
	}
}

func TestInternalHeadersNotLeakedToClient(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Signature", "internal-signature")
		w.Header().Set("X-Gateway", "tools-bpbj-core")
		w.Header().Set("X-Tool-Slug", "leak-tool")
		w.Header().Set("X-Access-Type", "public")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	router := newGatewayRouter(t, newLookup(activeTool("leak-tool", upstream.URL)), gateway.Options{})
	rec := doRequest(t, router, httptest.NewRequest(http.MethodGet, "/t/leak-tool/", nil))

	for _, name := range []string{"X-Signature", "X-Gateway", "X-Tool-Slug", "X-Access-Type"} {
		if v := rec.Header().Get(name); v != "" {
			t.Errorf("internal header %s leaked to client: %q", name, v)
		}
	}
}

// ------------------------------------------------------------ error handling

func TestUpstreamTimeoutReturns504(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	defer close(release)

	router := newGatewayRouter(t, newLookup(activeTool("slow-tool", upstream.URL)), gateway.Options{
		ResponseHeaderTimeout: 200 * time.Millisecond,
	})

	start := time.Now()
	rec := doRequest(t, router, httptest.NewRequest(http.MethodGet, "/t/slow-tool/", nil))
	elapsed := time.Since(start)

	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504 (body=%q)", rec.Code, rec.Body.String())
	}
	if elapsed > 5*time.Second {
		t.Errorf("timeout took %s, expected it to be bounded", elapsed)
	}
}

func TestConnectionRefusedReturns502(t *testing.T) {
	// Grab a free port, then close it so nothing is listening.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	router := newGatewayRouter(t, newLookup(activeTool("dead-tool", "http://"+addr)), gateway.Options{})

	rec := doRequest(t, router, httptest.NewRequest(http.MethodGet, "/t/dead-tool/", nil))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if strings.Contains(rec.Body.String(), addr) {
		t.Errorf("response leaked upstream address: %q", rec.Body.String())
	}
}

func TestDisallowedUpstreamNotContacted(t *testing.T) {
	called := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	realValidator := func(raw string) error {
		return service.ValidateUpstream(raw, service.NewUpstreamAllowlist())
	}
	router := newGatewayRouter(t, newLookup(activeTool("ssrf-tool", upstream.URL)), gateway.Options{
		UpstreamValidator: realValidator,
	})

	rec := doRequest(t, router, httptest.NewRequest(http.MethodGet, "/t/ssrf-tool/", nil))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if called {
		t.Error("upstream must not be contacted when validation fails")
	}
}

func TestOversizedRequestBodyRejected(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	router := newGatewayRouter(t, newLookup(activeTool("limit-tool", upstream.URL)), gateway.Options{
		MaxBodyBytes: 8,
	})

	req := httptest.NewRequest(http.MethodPost, "/t/limit-tool/upload", strings.NewReader("0123456789ABCDEF"))
	rec := doRequest(t, router, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413 (body=%q)", rec.Code, rec.Body.String())
	}
}

func TestUpstreamRedirectNotFollowed(t *testing.T) {
	var targetCalls int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetCalls++
		_, _ = w.Write([]byte("redirect-target"))
	}))
	defer target.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/elsewhere", http.StatusFound)
	}))
	defer upstream.Close()

	router := newGatewayRouter(t, newLookup(activeTool("redir-tool", upstream.URL)), gateway.Options{})
	rec := doRequest(t, router, httptest.NewRequest(http.MethodGet, "/t/redir-tool/", nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 passed through unfollowed", rec.Code)
	}
	if targetCalls != 0 {
		t.Errorf("redirect was followed: target called %d times", targetCalls)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "/elsewhere") {
		t.Errorf("Location = %q, want to contain /elsewhere", loc)
	}
}

// ---------------------------------------------------------------- streaming

// chunkThenBlockReader yields a fixed first chunk and then blocks until it is
// released. It proves the gateway forwards bytes as they arrive instead of
// reading the whole body into memory first.
type chunkThenBlockReader struct {
	chunk []byte
	block chan struct{}
}

func (r *chunkThenBlockReader) Read(p []byte) (int, error) {
	if len(r.chunk) > 0 {
		n := copy(p, r.chunk)
		r.chunk = r.chunk[n:]
		return n, nil
	}
	<-r.block
	return 0, io.EOF
}

func TestRequestBodyStreamedNotBuffered(t *testing.T) {
	const chunkSize = 64 * 1024

	// The upstream reports the first chunk as soon as it arrives, then keeps
	// reading. Observing that signal while the client body is still open proves
	// bytes are forwarded incrementally rather than buffered until completion.
	got := make(chan int, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, chunkSize)
		n, err := io.ReadFull(r.Body, buf)
		if err != nil {
			got <- -1
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		got <- n
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strconv.Itoa(n)))
	}))
	defer upstream.Close()

	router := newGatewayRouter(t, newLookup(activeTool("stream-tool", upstream.URL)), gateway.Options{})

	block := make(chan struct{})
	body := &chunkThenBlockReader{
		chunk: bytes.Repeat([]byte("a"), chunkSize),
		block: block,
	}
	req := httptest.NewRequest(http.MethodPost, "/t/stream-tool/upload", body)
	req.Header.Set("Content-Type", "application/octet-stream")

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		done <- rec
	}()

	select {
	case n := <-got:
		if n != chunkSize {
			t.Fatalf("upstream read %d bytes before the body completed, want %d", n, chunkSize)
		}
	case <-time.After(5 * time.Second):
		close(block)
		t.Fatal("gateway buffered the request body instead of streaming it")
	}

	close(block) // release the remainder so the exchange can finish

	select {
	case rec := <-done:
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body=%q)", rec.Code, rec.Body.String())
		}
		if got := rec.Body.String(); got != strconv.Itoa(chunkSize) {
			t.Errorf("body = %q, want %d", got, chunkSize)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("gateway did not complete the proxy exchange")
	}
}

func TestResponseStreamedWithFlush(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("part1"))
		w.(http.Flusher).Flush()
		<-release
		_, _ = w.Write([]byte("part2"))
	}))
	defer upstream.Close()
	defer close(release)

	router := newGatewayRouter(t, newLookup(activeTool("flush-tool", upstream.URL)), gateway.Options{})
	srv := httptest.NewServer(router)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/t/flush-tool/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	reader := bufio.NewReader(resp.Body)
	first := make([]byte, 5)
	readDone := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(reader, first)
		readDone <- err
	}()

	select {
	case err := <-readDone:
		if err != nil {
			t.Fatalf("read first chunk: %v", err)
		}
		if string(first) != "part1" {
			t.Errorf("first chunk = %q, want part1", string(first))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("response was buffered instead of streamed")
	}
}

// ---------------------------------------------------------------- slug safety

func TestInvalidSlugReturns404(t *testing.T) {
	lookup := newLookup()
	router := newGatewayRouter(t, lookup, gateway.Options{})

	for _, path := range []string{"/t/UPPER-Case/", "/t/has_underscore/", "/t/-leading/"} {
		rec := doRequest(t, router, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("path %s: status = %d, want 404", path, rec.Code)
		}
	}
	if lookup.calls != 0 {
		t.Errorf("repository was queried %d times for invalid slugs, want 0", lookup.calls)
	}
}

func TestConcurrentRequestsAreIsolated(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.URL.Path))
	}))
	defer upstream.Close()

	router := newGatewayRouter(t, newLookup(activeTool("iso-tool", upstream.URL)), gateway.Options{})

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			path := "/t/iso-tool/" + strings.Repeat("x", i+1)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code != http.StatusOK {
				t.Errorf("status = %d for %s", rec.Code, path)
				return
			}
			want := "/" + strings.Repeat("x", i+1)
			if got := rec.Body.String(); got != want {
				t.Errorf("body = %q, want %q", got, want)
			}
		}(i)
	}
	wg.Wait()
}
