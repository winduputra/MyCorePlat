package gateway_test

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/winduputra/MyCorePlat/internal/gateway"
	"github.com/winduputra/MyCorePlat/pkg/toolauth"
)

const (
	signingToolSlug      = "signed-tool"
	signingKeyID         = "k-2026-11"
	signingPreviousKeyID = "k-2026-10"
)

// signingSecret returns a deterministic secret that satisfies the minimum
// secret length enforced by toolauth.NewKey.
func signingSecret(label string) []byte {
	return []byte("test-secret-" + label + "-0123456789")
}

// testSigningStack writes a per-tool key file, then returns the signer Core uses
// and a verifier that models what the tool would run.
func testSigningStack(t *testing.T) (*toolauth.Signer, *toolauth.Verifier) {
	t.Helper()

	dir := t.TempDir()
	payload := `{"toolSlug":"` + signingToolSlug + `","keys":[` +
		`{"keyId":"` + signingKeyID + `","secret":"` + base64.StdEncoding.EncodeToString(signingSecret("active")) + `","status":"active"},` +
		`{"keyId":"` + signingPreviousKeyID + `","secret":"` + base64.StdEncoding.EncodeToString(signingSecret("previous")) + `","status":"previous"}` +
		`]}`
	if err := os.WriteFile(filepath.Join(dir, signingToolSlug+".json"), []byte(payload), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	active, err := toolauth.NewKey(signingKeyID, signingSecret("active"), toolauth.KeyStatusActive, nil)
	if err != nil {
		t.Fatalf("NewKey(active): %v", err)
	}
	previous, err := toolauth.NewKey(signingPreviousKeyID, signingSecret("previous"), toolauth.KeyStatusPrevious, nil)
	if err != nil {
		t.Fatalf("NewKey(previous): %v", err)
	}
	keys, err := toolauth.NewKeySet(active, previous)
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}

	verifier := &toolauth.Verifier{
		Keys:       keys,
		Skew:       toolauth.DefaultSkew,
		NonceStore: toolauth.NewInMemoryNonceStore(),
		Now:        time.Now,
	}
	return toolauth.NewSigner(toolauth.NewFileKeyStore(dir)), verifier
}

// verifyingUpstream records what the tool received and runs the tool-side
// verification contract against it.
type verifyingUpstream struct {
	*httptest.Server
	verifier   *toolauth.Verifier
	verifyErr  error
	header     http.Header
	trailer    http.Header
	body       []byte
	requestCnt int
	lastPath   string
	lastQuery  string
}

func newVerifyingUpstream(t *testing.T, verifier *toolauth.Verifier) *verifyingUpstream {
	t.Helper()
	vu := &verifyingUpstream{verifier: verifier}
	vu.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		vu.requestCnt++
		vu.header = r.Header.Clone()
		vu.trailer = r.Trailer.Clone()
		vu.body = raw
		vu.lastPath = r.URL.EscapedPath()
		vu.lastQuery = r.URL.RawQuery
		vu.verifyErr = vu.verifier.Verify(r.Context(), toolauth.VerifyInput{
			Method:     r.Method,
			Path:       r.URL.EscapedPath(),
			Query:      r.URL.RawQuery,
			Header:     r.Header,
			Trailer:    r.Trailer,
			BodySHA256: toolauth.BodyHash(raw),
		})
		if vu.verifyErr != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("signed-ok"))
	}))
	t.Cleanup(vu.Close)
	return vu
}

func TestGatewaySignsBufferedBodyRequestAcceptedByTool(t *testing.T) {
	signer, verifier := testSigningStack(t)
	upstream := newVerifyingUpstream(t, verifier)

	router := newGatewayRouter(t, newLookup(activeTool(signingToolSlug, upstream.URL)), gateway.Options{
		UpstreamValidator: permissiveValidator,
		Signer:            signer,
	})

	body := "hello tool"
	req := httptest.NewRequest(http.MethodPost, "/t/"+signingToolSlug+"/echo?a=1&b=two", strings.NewReader(body))
	req.ContentLength = int64(len(body))
	rec := doRequest(t, router, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	if upstream.verifyErr != nil {
		t.Fatalf("tool rejected Core signature: %v", upstream.verifyErr)
	}
	if got := upstream.header.Get(toolauth.HeaderKeyID); got != signingKeyID {
		t.Errorf("key id = %q, want %q", got, signingKeyID)
	}
	if upstream.header.Get(toolauth.HeaderSignature) == "" {
		t.Error("missing X-Signature header")
	}
	if upstream.header.Get(toolauth.HeaderNonce) == "" {
		t.Error("missing X-Signature-Nonce header")
	}
	if got := upstream.header.Get(toolauth.HeaderGateway); got != toolauth.GatewayIdentifier {
		t.Errorf("X-Gateway = %q, want %q", got, toolauth.GatewayIdentifier)
	}
	if upstream.lastPath != "/echo" || upstream.lastQuery != "a=1&b=two" {
		t.Errorf("forwarded path/query = %q / %q", upstream.lastPath, upstream.lastQuery)
	}
	if string(upstream.body) != body {
		t.Errorf("forwarded body = %q, want %q", upstream.body, body)
	}
}

func TestGatewaySignsBodylessRequestWithEmptyBodyHash(t *testing.T) {
	signer, verifier := testSigningStack(t)
	upstream := newVerifyingUpstream(t, verifier)

	router := newGatewayRouter(t, newLookup(activeTool(signingToolSlug, upstream.URL)), gateway.Options{
		UpstreamValidator: permissiveValidator,
		Signer:            signer,
	})

	rec := doRequest(t, router, httptest.NewRequest(http.MethodGet, "/t/"+signingToolSlug+"/health", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if upstream.verifyErr != nil {
		t.Fatalf("tool rejected Core signature for bodyless request: %v", upstream.verifyErr)
	}
	if len(upstream.body) != 0 {
		t.Errorf("forwarded body = %q, want empty", upstream.body)
	}
}

func TestGatewayUsesActiveKeyForSigning(t *testing.T) {
	signer, verifier := testSigningStack(t)
	upstream := newVerifyingUpstream(t, verifier)

	router := newGatewayRouter(t, newLookup(activeTool(signingToolSlug, upstream.URL)), gateway.Options{
		UpstreamValidator: permissiveValidator,
		Signer:            signer,
	})

	rec := doRequest(t, router, httptest.NewRequest(http.MethodGet, "/t/"+signingToolSlug+"/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := upstream.header.Get(toolauth.HeaderKeyID); got != signingKeyID {
		t.Errorf("signed with key id %q, want active key %q", got, signingKeyID)
	}
}

func TestGatewayOverridesClientSuppliedSignatureHeaders(t *testing.T) {
	signer, verifier := testSigningStack(t)
	upstream := newVerifyingUpstream(t, verifier)

	router := newGatewayRouter(t, newLookup(activeTool(signingToolSlug, upstream.URL)), gateway.Options{
		UpstreamValidator: permissiveValidator,
		Signer:            signer,
	})

	req := httptest.NewRequest(http.MethodGet, "/t/"+signingToolSlug+"/health", nil)
	req.Header.Set(toolauth.HeaderSignature, "deadbeef")
	req.Header.Set(toolauth.HeaderKeyID, "attacker-key")
	req.Header.Set(toolauth.HeaderTimestamp, "1")
	req.Header.Set(toolauth.HeaderNonce, "attacker-nonce")

	rec := doRequest(t, router, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (client headers must be replaced, not merged)", rec.Code)
	}
	if upstream.verifyErr != nil {
		t.Fatalf("tool rejected Core signature: %v", upstream.verifyErr)
	}
	if got := upstream.header.Get(toolauth.HeaderSignature); got == "deadbeef" {
		t.Error("client-supplied X-Signature was forwarded unchanged")
	}
	if got := upstream.header.Get(toolauth.HeaderKeyID); got != signingKeyID {
		t.Errorf("key id = %q, want %q", got, signingKeyID)
	}
	if got := upstream.header.Get(toolauth.HeaderNonce); got == "attacker-nonce" {
		t.Error("client-supplied nonce was forwarded unchanged")
	}
}

func TestGatewayNonceIsUniquePerRequest(t *testing.T) {
	signer, verifier := testSigningStack(t)
	upstream := newVerifyingUpstream(t, verifier)

	router := newGatewayRouter(t, newLookup(activeTool(signingToolSlug, upstream.URL)), gateway.Options{
		UpstreamValidator: permissiveValidator,
		Signer:            signer,
	})

	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		rec := doRequest(t, router, httptest.NewRequest(http.MethodGet, "/t/"+signingToolSlug+"/health", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i, rec.Code)
		}
		nonce := upstream.header.Get(toolauth.HeaderNonce)
		if nonce == "" {
			t.Fatalf("request %d: missing nonce", i)
		}
		if seen[nonce] {
			t.Fatalf("request %d: nonce %q reused across requests", i, nonce)
		}
		seen[nonce] = true
	}
}

func TestGatewaySignsStreamedBodyWithDigestTrailer(t *testing.T) {
	signer, verifier := testSigningStack(t)
	upstream := newVerifyingUpstream(t, verifier)

	router := newGatewayRouter(t, newLookup(activeTool(signingToolSlug, upstream.URL)), gateway.Options{
		UpstreamValidator: permissiveValidator,
		Signer:            signer,
	})

	payload := strings.Repeat("streamed-payload-", 64)
	req := httptest.NewRequest(http.MethodPost, "/t/"+signingToolSlug+"/upload", strings.NewReader(payload))
	// Unknown length: the gateway must stream and bind the digest via trailer.
	req.ContentLength = -1

	rec := doRequest(t, router, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	if string(upstream.body) != payload {
		t.Fatalf("forwarded body length = %d, want %d", len(upstream.body), len(payload))
	}
	if upstream.verifyErr != nil {
		t.Fatalf("tool rejected signed streamed request: %v", upstream.verifyErr)
	}
	wantDigest := "sha-256=" + toolauth.BodyHash([]byte(payload))
	if got := upstream.trailer.Get(toolauth.HeaderBodyDigest); got != wantDigest {
		t.Errorf("trailer %s = %q, want %q", toolauth.HeaderBodyDigest, got, wantDigest)
	}
	if upstream.trailer.Get(toolauth.HeaderBodySignature) == "" {
		t.Errorf("trailer %s missing", toolauth.HeaderBodySignature)
	}
}

func TestGatewayStreamsLargeKnownLengthBodyWithTrailer(t *testing.T) {
	signer, verifier := testSigningStack(t)
	upstream := newVerifyingUpstream(t, verifier)

	const signBuffer = 64
	router := newGatewayRouter(t, newLookup(activeTool(signingToolSlug, upstream.URL)), gateway.Options{
		UpstreamValidator: permissiveValidator,
		Signer:            signer,
		SignBufferBytes:   signBuffer,
	})

	payload := strings.Repeat("x", signBuffer*4)
	req := httptest.NewRequest(http.MethodPost, "/t/"+signingToolSlug+"/upload", strings.NewReader(payload))
	req.ContentLength = int64(len(payload))

	rec := doRequest(t, router, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if string(upstream.body) != payload {
		t.Fatalf("forwarded body length = %d, want %d", len(upstream.body), len(payload))
	}
	if upstream.verifyErr != nil {
		t.Fatalf("tool rejected signed streamed request: %v", upstream.verifyErr)
	}
}

func TestGatewayFailsClosedWhenSigningKeyMissing(t *testing.T) {
	// Empty key directory: no key exists for the tool, so signing must fail and
	// the request must NOT reach the tool.
	signer := toolauth.NewSigner(toolauth.NewFileKeyStore(t.TempDir()))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("unsigned request reached the tool")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	router := newGatewayRouter(t, newLookup(activeTool(signingToolSlug, upstream.URL)), gateway.Options{
		UpstreamValidator: permissiveValidator,
		Signer:            signer,
	})

	rec := doRequest(t, router, httptest.NewRequest(http.MethodGet, "/t/"+signingToolSlug+"/health", nil))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 when signing is impossible", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "key") || strings.Contains(rec.Body.String(), "secret") {
		t.Errorf("error body leaks signing detail: %q", rec.Body.String())
	}
}

func TestGatewayUnsignedModeStillProxies(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(toolauth.HeaderSignature) != "" {
			t.Error("unsigned mode must not add a signature header")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// No Signer configured: development-only behaviour, unchanged from Task 7.
	router := newGatewayRouter(t, newLookup(activeTool(signingToolSlug, upstream.URL)), gateway.Options{
		UpstreamValidator: permissiveValidator,
	})

	rec := doRequest(t, router, httptest.NewRequest(http.MethodGet, "/t/"+signingToolSlug+"/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

var _ gateway.RequestSigner = (*toolauth.Signer)(nil)
