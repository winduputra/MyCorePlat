package gateway_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/winduputra/MyCorePlat/internal/gateway"
	"github.com/winduputra/MyCorePlat/internal/service"
)

// keyRecorderLimiter records the keys it was asked about and always allows, so a
// test can prove which address the gateway throttled on.
type keyRecorderLimiter struct {
	seen []string
}

func (l *keyRecorderLimiter) Allow(key string) bool {
	l.seen = append(l.seen, key)
	return true
}

func gatewayResolver(t *testing.T, trusted ...string) *service.ClientIPResolver {
	t.Helper()
	resolver, err := service.NewClientIPResolver(trusted)
	if err != nil {
		t.Fatalf("NewClientIPResolver(%v): %v", trusted, err)
	}
	return resolver
}

// gatewayRequest drives the engine with an explicit TCP peer and optional
// X-Forwarded-For / bearer token.
func gatewayRequest(t *testing.T, r *gin.Engine, remoteAddr, forwardedFor, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = remoteAddr
	if forwardedFor != "" {
		req.Header.Set("X-Forwarded-For", forwardedFor)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// upstreamForwardedFor reports the X-Forwarded-For it received, so the test can
// assert which client address Core told the tool about.
func upstreamForwardedFor(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-XFF", r.Header.Get("X-Forwarded-For"))
		w.WriteHeader(http.StatusOK)
	}))
}

// TestGatewayTrustedProxyUsesForwardedClientForXFF asserts that when the peer is
// a trusted proxy, the client address reported to the tool is the forwarded
// client, not the proxy address.
func TestGatewayTrustedProxyUsesForwardedClientForXFF(t *testing.T) {
	upstream := upstreamForwardedFor(t)
	defer upstream.Close()
	tool := activeTool("proxy-xff-tool", upstream.URL)

	router := newGatewayRouter(t, newLookup(tool), gateway.Options{
		UpstreamValidator: func(string) error { return nil },
		IPPolicy:          service.NewLoopbackUpstreamPolicyForTests(),
		ClientIPResolver:  gatewayResolver(t, "172.18.0.3"),
	})

	w := gatewayRequest(t, router, "172.18.0.3:40212", "36.72.11.9", "/t/proxy-xff-tool/", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if got := w.Header().Get("X-Seen-XFF"); got != "36.72.11.9" {
		t.Fatalf("tool saw X-Forwarded-For %q, want the forwarded client 36.72.11.9", got)
	}
}

// TestGatewayUntrustedPeerForwardedClientIsIgnored asserts a direct client
// cannot choose the address Core forwards to the tool.
func TestGatewayUntrustedPeerForwardedClientIsIgnored(t *testing.T) {
	upstream := upstreamForwardedFor(t)
	defer upstream.Close()
	tool := activeTool("proxy-xff-tool2", upstream.URL)

	router := newGatewayRouter(t, newLookup(tool), gateway.Options{
		UpstreamValidator: func(string) error { return nil },
		IPPolicy:          service.NewLoopbackUpstreamPolicyForTests(),
		ClientIPResolver:  gatewayResolver(t, "172.18.0.3"),
	})

	w := gatewayRequest(t, router, "45.33.10.20:5555", "1.2.3.4", "/t/proxy-xff-tool2/", "")
	if got := w.Header().Get("X-Seen-XFF"); got != "45.33.10.20" {
		t.Fatalf("tool saw X-Forwarded-For %q, want the real peer 45.33.10.20", got)
	}
}

// TestGatewayTokenLimiterUsesResolvedClient asserts the token limiter is keyed
// on the forwarded client when the peer is a trusted proxy.
func TestGatewayTokenLimiterUsesResolvedClient(t *testing.T) {
	upstream := upstreamForwardedFor(t)
	defer upstream.Close()
	tool := tokenTool(9, "proxy-token-tool", upstream.URL)

	validator := newFakeTokenValidator()
	validator.allow("goodtoken", 9)
	limiter := &keyRecorderLimiter{}

	router := newGatewayRouter(t, newLookup(tool), gateway.Options{
		UpstreamValidator: func(string) error { return nil },
		IPPolicy:          service.NewLoopbackUpstreamPolicyForTests(),
		TokenValidator:    validator,
		TokenRateLimiter:  limiter,
		ClientIPResolver:  gatewayResolver(t, "172.18.0.3"),
	})

	w := gatewayRequest(t, router, "172.18.0.3:40212", "36.72.11.9", "/t/proxy-token-tool/", "goodtoken")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if len(limiter.seen) == 0 || !strings.Contains(limiter.seen[len(limiter.seen)-1], "36.72.11.9") {
		t.Fatalf("token limiter keys = %v, want one keyed on the forwarded client 36.72.11.9", limiter.seen)
	}
}
