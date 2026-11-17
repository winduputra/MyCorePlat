package gateway_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/winduputra/MyCorePlat/internal/gateway"
	"github.com/winduputra/MyCorePlat/internal/model"
	"github.com/winduputra/MyCorePlat/internal/service"
)

// ------------------------------------------------------------ resolver doubles

// stubResolver is a controlled resolver: no test depends on real DNS.
type stubResolver struct {
	mu      sync.Mutex
	answers map[string][]string
	err     error
	calls   int
	hosts   []string
}

func newStubResolver(answers map[string][]string) *stubResolver {
	return &stubResolver{answers: answers}
}

func (s *stubResolver) LookupIP(_ context.Context, host string) ([]net.IP, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.hosts = append(s.hosts, host)
	if s.err != nil {
		return nil, s.err
	}
	addrs, ok := s.answers[host]
	if !ok {
		return nil, fmt.Errorf("no such host %q", host)
	}
	out := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			return nil, fmt.Errorf("invalid test address %q", addr)
		}
		out = append(out, ip)
	}
	return out, nil
}

func (s *stubResolver) setAnswers(host string, addrs ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.answers[host] = addrs
}

func (s *stubResolver) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *stubResolver) resolvedHosts() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.hosts...)
}

// allowlistValidator enforces the hostname allowlist while ignoring the port, so
// tests can use httptest servers on ephemeral ports.
func allowlistValidator(allow service.UpstreamAllowlist) func(string) error {
	return func(raw string) error {
		parsed, err := url.Parse(raw)
		if err != nil {
			return err
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return fmt.Errorf("scheme %q not allowed", parsed.Scheme)
		}
		host := parsed.Hostname()
		if net.ParseIP(host) != nil {
			return nil
		}
		if !allow.Contains(host) {
			return fmt.Errorf("host %q not allowed", host)
		}
		return nil
	}
}

// hostnameTool builds a tool whose upstream uses a hostname that only the test
// resolver can resolve.
func hostnameTool(slug, rawURL string) *model.Tool { return activeTool(slug, rawURL) }

// ------------------------------------------------------- resolution & pinning

func TestGatewayRejectsHostnameOutsideAllowlistBeforeResolving(t *testing.T) {
	resolver := newStubResolver(map[string][]string{"evil.internal": {"10.0.0.5"}})
	allow := service.NewUpstreamAllowlist("tool.internal")

	router := newGatewayRouter(t, newLookup(hostnameTool("host-tool", "http://evil.internal:9000")), gateway.Options{
		Resolver:          resolver,
		UpstreamAllowlist: allow,
		UpstreamValidator: allowlistValidator(allow),
		IPPolicy:          service.DefaultUpstreamIPPolicy(),
	})

	rec := doRequest(t, router, httptest.NewRequest(http.MethodGet, "/t/host-tool/x", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if resolver.callCount() != 0 {
		t.Errorf("resolver calls = %d, want 0 for a non-allowlisted host", resolver.callCount())
	}
	if body := rec.Body.String(); containsFold(body, "evil.internal") {
		t.Errorf("error body leaked the host: %q", body)
	}
}

func TestGatewayDialsValidatedIPForAllowlistedHostname(t *testing.T) {
	var gotHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("pinned-ok"))
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	allow := service.NewUpstreamAllowlist("tool.internal")
	resolver := newStubResolver(map[string][]string{"tool.internal": {"127.0.0.1"}})

	router := newGatewayRouter(t, newLookup(hostnameTool("pin-tool", "http://tool.internal:"+upstreamURL.Port())), gateway.Options{
		Resolver:          resolver,
		UpstreamAllowlist: allow,
		UpstreamValidator: allowlistValidator(allow),
	})

	rec := doRequest(t, router, httptest.NewRequest(http.MethodGet, "/t/pin-tool/x", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "pinned-ok" {
		t.Fatalf("status = %d body = %q, want 200 pinned-ok", rec.Code, rec.Body.String())
	}
	if resolver.callCount() != 1 {
		t.Errorf("resolver calls = %d, want exactly 1 per new connection", resolver.callCount())
	}
	if want := "tool.internal:" + upstreamURL.Port(); gotHost != want {
		t.Errorf("upstream Host = %q, want %q (original hostname)", gotHost, want)
	}
}

func TestGatewayRejectsRebindingAfterValidation(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	allow := service.NewUpstreamAllowlist("tool.internal")
	// First connection resolves to loopback; afterwards the name "rebinds" to a
	// denied documentation address.
	resolver := newStubResolver(map[string][]string{"tool.internal": {"127.0.0.1"}})

	router := newGatewayRouter(t, newLookup(hostnameTool("rebind-tool", "http://tool.internal:"+upstreamURL.Port())), gateway.Options{
		Resolver:          resolver,
		UpstreamAllowlist: allow,
		UpstreamValidator: allowlistValidator(allow),
		IPPolicy:          service.NewLoopbackUpstreamPolicyForTests(),
	})

	if rec := doRequest(t, router, httptest.NewRequest(http.MethodGet, "/t/rebind-tool/a", nil)); rec.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", rec.Code)
	}

	resolver.setAnswers("tool.internal", "192.0.2.10")

	// A new connection re-validates and must fail closed instead of silently
	// connecting to the rebound (denied) address.
	second := doRequest(t, router, httptest.NewRequest(http.MethodGet, "/t/rebind-tool/b", nil))
	if second.Code != http.StatusOK && second.Code != http.StatusBadGateway {
		t.Fatalf("second request status = %d, want 200 (pooled) or 502 (rebind denied)", second.Code)
	}
	if second.Code == http.StatusBadGateway {
		if containsFold(second.Body.String(), "192.0.2.10") {
			t.Errorf("error body leaked the resolved address: %q", second.Body.String())
		}
	}
}

func TestGatewayFailsClosedWhenResolutionFails(t *testing.T) {
	allow := service.NewUpstreamAllowlist("tool.internal")
	resolver := &stubResolver{err: errors.New("dns timeout"), answers: map[string][]string{}}

	router := newGatewayRouter(t, newLookup(hostnameTool("dns-fail-tool", "http://tool.internal:9000")), gateway.Options{
		Resolver:          resolver,
		UpstreamAllowlist: allow,
		UpstreamValidator: allowlistValidator(allow),
	})

	rec := doRequest(t, router, httptest.NewRequest(http.MethodGet, "/t/dns-fail-tool/x", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if resolver.callCount() == 0 {
		t.Error("resolver was never called")
	}
	if containsFold(rec.Body.String(), "dns timeout") {
		t.Errorf("error body leaked resolver detail: %q", rec.Body.String())
	}
}

func TestGatewayFailsClosedOnEmptyResolution(t *testing.T) {
	allow := service.NewUpstreamAllowlist("tool.internal")
	resolver := newStubResolver(map[string][]string{"tool.internal": {}})

	router := newGatewayRouter(t, newLookup(hostnameTool("dns-empty-tool", "http://tool.internal:9000")), gateway.Options{
		Resolver:          resolver,
		UpstreamAllowlist: allow,
		UpstreamValidator: allowlistValidator(allow),
	})

	if rec := doRequest(t, router, httptest.NewRequest(http.MethodGet, "/t/dns-empty-tool/x", nil)); rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 for an empty DNS answer", rec.Code)
	}
}

func TestGatewayRejectsHostnameWithAnyDeniedAddress(t *testing.T) {
	allow := service.NewUpstreamAllowlist("mixed.internal")
	// One acceptable answer plus a metadata address: the whole name is denied.
	resolver := newStubResolver(map[string][]string{"mixed.internal": {"127.0.0.1", "169.254.169.254"}})

	upstreamCalled := int32(0)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamCalled, 1)
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	router := newGatewayRouter(t, newLookup(hostnameTool("mixed-tool", "http://mixed.internal:"+upstreamURL.Port())), gateway.Options{
		Resolver:          resolver,
		UpstreamAllowlist: allow,
		UpstreamValidator: allowlistValidator(allow),
	})

	if rec := doRequest(t, router, httptest.NewRequest(http.MethodGet, "/t/mixed-tool/x", nil)); rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if atomic.LoadInt32(&upstreamCalled) != 0 {
		t.Error("upstream was contacted despite a denied DNS answer")
	}
}

func TestGatewayConcurrentHostnameRequestsAreSafe(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	allow := service.NewUpstreamAllowlist("tool.internal")
	resolver := newStubResolver(map[string][]string{"tool.internal": {"127.0.0.1"}})
	router := newGatewayRouter(t, newLookup(hostnameTool("conc-tool", "http://tool.internal:"+upstreamURL.Port())), gateway.Options{
		Resolver:          resolver,
		UpstreamAllowlist: allow,
		UpstreamValidator: allowlistValidator(allow),
	})

	var wg sync.WaitGroup
	errCh := make(chan string, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := doRequest(t, router, httptest.NewRequest(http.MethodGet, "/t/conc-tool/x", nil))
			if rec.Code != http.StatusOK {
				errCh <- fmt.Sprintf("status = %d", rec.Code)
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for msg := range errCh {
		t.Error(msg)
	}
	for _, host := range resolver.resolvedHosts() {
		if host != "tool.internal" {
			t.Errorf("unexpected host resolved: %q", host)
		}
	}
}

// ------------------------------------------------------------ TLS SNI + Host

func TestGatewayKeepsHostnameForTLSAndHostHeader(t *testing.T) {
	const hostname = "tool.internal"

	sni := make(chan string, 1)
	cert, pool := generateCert(t, hostname)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "" || r.Host[:len(hostname)] != hostname {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte("tls-ok"))
	})

	upstream := httptest.NewUnstartedServer(handler)
	upstream.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			select {
			case sni <- hello.ServerName:
			default:
			}
			return nil, nil
		},
	}
	upstream.StartTLS()
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	allow := service.NewUpstreamAllowlist(hostname)
	resolver := newStubResolver(map[string][]string{hostname: {"127.0.0.1"}})

	router := newGatewayRouter(t, newLookup(hostnameTool("tls-tool", "https://"+hostname+":"+upstreamURL.Port())), gateway.Options{
		Resolver:          resolver,
		UpstreamAllowlist: allow,
		UpstreamValidator: allowlistValidator(allow),
		TLSRootCAs:        pool,
	})

	rec := doRequest(t, router, httptest.NewRequest(http.MethodGet, "/t/tls-tool/x", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "tls-ok" {
		t.Fatalf("status = %d body = %q, want 200 tls-ok", rec.Code, rec.Body.String())
	}

	select {
	case got := <-sni:
		if got != hostname {
			t.Errorf("TLS SNI = %q, want %q", got, hostname)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no TLS handshake observed")
	}
}

func TestGatewayRejectsTLSCertificateForWrongHostname(t *testing.T) {
	cert, pool := generateCert(t, "other.internal")
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	upstream.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	upstream.StartTLS()
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	allow := service.NewUpstreamAllowlist("tool.internal")
	resolver := newStubResolver(map[string][]string{"tool.internal": {"127.0.0.1"}})

	router := newGatewayRouter(t, newLookup(hostnameTool("tls-bad-tool", "https://tool.internal:"+upstreamURL.Port())), gateway.Options{
		Resolver:          resolver,
		UpstreamAllowlist: allow,
		UpstreamValidator: allowlistValidator(allow),
		TLSRootCAs:        pool,
	})

	if rec := doRequest(t, router, httptest.NewRequest(http.MethodGet, "/t/tls-bad-tool/x", nil)); rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 for a certificate that does not match the hostname", rec.Code)
	}
}

// ------------------------------------------------------------- redirect policy

func TestGatewayDoesNotForwardRedirectToMetadataAddress(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://169.254.169.254/latest/meta-data/")
		w.WriteHeader(http.StatusFound)
	}))
	defer upstream.Close()

	router := newGatewayRouter(t, newLookup(activeTool("redirect-tool", upstream.URL)), gateway.Options{})

	rec := doRequest(t, router, httptest.NewRequest(http.MethodGet, "/t/redirect-tool/x", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("Location = %q, want it dropped", loc)
	}
}

func TestGatewayDoesNotForwardRedirectToNonAllowlistedHost(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://attacker.example.com/steal")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer upstream.Close()

	allow := service.NewUpstreamAllowlist("tool.internal")
	router := newGatewayRouter(t, newLookup(activeTool("redirect-tool", upstream.URL)), gateway.Options{
		UpstreamAllowlist: allow,
		UpstreamValidator: allowlistValidator(allow),
	})

	rec := doRequest(t, router, httptest.NewRequest(http.MethodGet, "/t/redirect-tool/x", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("Location = %q, want it dropped", loc)
	}
}

func TestGatewayForwardsValidatedRelativeRedirect(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/moved/here")
		w.WriteHeader(http.StatusFound)
	}))
	defer upstream.Close()

	router := newGatewayRouter(t, newLookup(activeTool("redirect-tool", upstream.URL)), gateway.Options{})

	rec := doRequest(t, router, httptest.NewRequest(http.MethodGet, "/t/redirect-tool/x", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/moved/here" {
		t.Errorf("Location = %q, want /moved/here", loc)
	}
}

func TestGatewayForwardsRedirectToValidatedAllowlistedHost(t *testing.T) {
	const hostname = "tool.internal"

	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer redirectTarget.Close()
	targetURL, _ := url.Parse(redirectTarget.URL)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://"+hostname+":"+targetURL.Port()+"/next")
		w.WriteHeader(http.StatusFound)
	}))
	defer upstream.Close()

	allow := service.NewUpstreamAllowlist(hostname)
	resolver := newStubResolver(map[string][]string{hostname: {"127.0.0.1"}})

	router := newGatewayRouter(t, newLookup(activeTool("redirect-tool", upstream.URL)), gateway.Options{
		Resolver:          resolver,
		UpstreamAllowlist: allow,
		UpstreamValidator: allowlistValidator(allow),
	})

	rec := doRequest(t, router, httptest.NewRequest(http.MethodGet, "/t/redirect-tool/x", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc == "" {
		t.Error("Location header missing for a validated redirect target")
	}
}

// --------------------------------------------------------------------- helpers

func generateCert(t *testing.T, hostname string) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: hostname},
		DNSNames:              []string{hostname},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)

	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return cert, pool
}

func containsFold(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if equalFold(haystack[i:i+len(needle)], needle) {
				return true
			}
		}
		return false
	})()
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
