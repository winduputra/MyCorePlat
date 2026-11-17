// Package gateway implements the reverse proxy that routes /t/{slug}/ requests
// to internal tool services after server-side authorization.
//
// Responsibilities and limits of this layer:
//
//   - The tool record is read from the database on every request; Status and
//     AccessType are enforced server-side and are never taken from client input.
//   - The upstream URL comes only from the tool record, never from the request.
//   - The upstream URL is checked against the exact host allowlist before any
//     connection is attempted.
//   - Request and response bodies are streamed; nothing is buffered in memory.
//   - Hop-by-hop headers and client-supplied identity/auth headers are dropped.
//   - Upstream redirects are never followed automatically.
//
// Not implemented here (by approved task sequencing): per-tool HMAC signing of
// forwarded requests (Task 8), and DNS-resolution/pinned-IP protection against
// DNS rebinding (Task 9). The allowlist check in this package is syntactic only;
// it does not prove that a hostname resolves to an internal address.
package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/winduputra/MyCorePlat/internal/model"
	"github.com/winduputra/MyCorePlat/internal/service"
	"github.com/winduputra/MyCorePlat/pkg/toolauth"
)

// Defaults for the upstream transport and the request body limit.
const (
	// DefaultMaxBodyBytes is the default cap on a forwarded request body.
	DefaultMaxBodyBytes int64 = 25 << 20 // 25 MiB
	// DefaultSignBufferBytes is the default largest body buffered in memory so
	// the signature can cover its exact hash. Longer or unknown-length bodies
	// are streamed and bound by a signed digest trailer instead.
	DefaultSignBufferBytes int64 = 1 << 20 // 1 MiB
	// DefaultConnectTimeout bounds dialing an upstream.
	DefaultConnectTimeout = 5 * time.Second
	// DefaultResponseHeaderTimeout bounds waiting for upstream response headers.
	// It is deliberately separate from any total-request deadline so that long
	// streaming responses are not cut off mid-flight.
	DefaultResponseHeaderTimeout = 60 * time.Second
	// DefaultIdleConnTimeout bounds idle keep-alive connections.
	DefaultIdleConnTimeout = 90 * time.Second
	// DefaultMaxIdleConns bounds the idle connection pool.
	DefaultMaxIdleConns = 64
	// DefaultMaxIdleConnsPerHost bounds idle connections kept per upstream.
	DefaultMaxIdleConnsPerHost = 16
	// DefaultTLSHandshakeTimeout bounds the TLS handshake to an upstream.
	DefaultTLSHandshakeTimeout = 5 * time.Second

	// gatewayIdentifier is sent to tools as X-Gateway. It is informational only;
	// caller authentication is the per-tool HMAC signature added in Task 8.
	gatewayIdentifier = "tools-bpbj-core"
)

// errBodyTooLarge is returned by the body limiter when a client sends more than
// the configured maximum number of bytes.
var errBodyTooLarge = errors.New("gateway: request body too large")

// slugPattern mirrors the slug rule enforced by the registry service. Slugs are
// canonical: no case folding, so one tool has exactly one URL.
var slugPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// hopByHopHeaders are connection-specific and must not be forwarded in either
// direction (RFC 7230 §6.1).
var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// strippedRequestHeaders are removed from client requests before forwarding:
// authentication material that belongs to Core or to the internal contract, and
// identity headers a client might try to spoof.
var strippedRequestHeaders = []string{
	// Core/admin credentials must never reach a tool.
	"Authorization",
	"Cookie",
	"Proxy-Authorization",
	"X-Csrf-Token",
	// Internal Core→tool authentication headers: clients cannot supply these.
	"X-Signature",
	"X-Signature-Key-Id",
	"X-Signature-Timestamp",
	"X-Signature-Nonce",
	"X-Signature-Body-Digest",
	// Context headers owned by the gateway.
	"X-Gateway",
	"X-Tool-Slug",
	"X-Access-Type",
	// Forwarding chain headers are recomputed, never inherited.
	"Forwarded",
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
	"X-Real-Ip",
	// Client-supplied identity is never trusted.
	"X-Admin-Id",
	"X-Admin",
	"X-User-Id",
	"X-User",
	"X-Role",
	"X-User-Role",
}

// strippedResponseHeaders are internal headers that must never reach a browser.
var strippedResponseHeaders = []string{
	"X-Signature",
	"X-Signature-Key-Id",
	"X-Signature-Timestamp",
	"X-Signature-Nonce",
	"X-Signature-Body-Digest",
	"X-Gateway",
	"X-Tool-Slug",
	"X-Access-Type",
}

// ToolLookup is the narrow read interface the gateway needs from the registry.
// *service.ToolService satisfies it.
type ToolLookup interface {
	GetBySlug(ctx context.Context, slug string) (*model.Tool, error)
}

// Options configures a Gateway. Zero values fall back to the defaults above.
type Options struct {
	// MaxBodyBytes caps the request body forwarded to a tool.
	MaxBodyBytes int64
	// ConnectTimeout bounds dialing an upstream.
	ConnectTimeout time.Duration
	// ResponseHeaderTimeout bounds waiting for upstream response headers.
	ResponseHeaderTimeout time.Duration
	// IdleConnTimeout bounds idle keep-alive connections.
	IdleConnTimeout time.Duration
	// UpstreamAllowlist is the exact set of internal hostnames an upstream URL
	// may use. It comes from server-side configuration only.
	UpstreamAllowlist service.UpstreamAllowlist
	// UpstreamValidator overrides the upstream URL validator. Production leaves
	// this nil so the allowlist validator is used. Tests set it because httptest
	// upstreams listen on 127.0.0.1 with random ports, which the production
	// validator rejects on purpose.
	UpstreamValidator func(rawURL string) error
	// Signer signs every forwarded request so the tool can verify it came from
	// Core. Nil disables signing, which is only acceptable in development and
	// tests; production refuses to start without a configured key directory.
	Signer RequestSigner
	// SignBufferBytes is the largest body buffered in memory so the signature
	// covers its exact hash. Larger or unknown-length bodies are streamed and
	// bound by a signed digest trailer.
	SignBufferBytes int64
	// Resolver resolves upstream hostnames. Nil uses the system resolver. DNS is
	// always consulted through this resolver, and every returned address is
	// validated before any connection is made.
	Resolver service.IPResolver
	// IPPolicy is the address policy applied to resolved upstream addresses and
	// to redirect targets. The zero value falls back to the approved default:
	// private/internal ranges only. Tests inject a loopback-permitting policy.
	IPPolicy service.UpstreamIPPolicy
	// TLSRootCAs overrides the roots used to verify tool TLS certificates. Nil
	// uses the system roots. Used for internal CAs and by tests.
	TLSRootCAs *x509.CertPool
	// TokenValidator authorizes access=token tools. Nil makes those tools
	// unreachable (fail closed), which is the correct default: a token tool must
	// never silently become public.
	TokenValidator TokenValidator
	// TokenRateLimiter throttles token validation attempts per source IP. Nil
	// disables throttling (acceptable only in tests).
	TokenRateLimiter TokenRateLimiter
	// ClientIPResolver derives the caller address for rate limiting and the
	// X-Forwarded-For header sent to tools. Nil trusts only the TCP peer
	// address (safe default); a configured resolver honours forwarding headers
	// only from trusted proxies.
	ClientIPResolver *service.ClientIPResolver
}

// TokenValidator authorizes a plaintext access token against the tool it is
// presented for. *service.AccessTokenService satisfies it.
type TokenValidator interface {
	Validate(ctx context.Context, plaintext string, toolID uint64, now time.Time) (*model.AccessToken, error)
	TouchLastUsed(ctx context.Context, id uint64, now time.Time)
}

// TokenRateLimiter throttles token validation attempts to blunt online token
// guessing. *service.RateLimiter satisfies it.
type TokenRateLimiter interface {
	Allow(key string) bool
}

var (
	_ TokenValidator   = (*service.AccessTokenService)(nil)
	_ TokenRateLimiter = (*service.RateLimiter)(nil)
)

// RequestSigner signs one outbound Core -> Tool request. *toolauth.Signer
// satisfies it; the digest-trailer method is only used for streamed bodies.
type RequestSigner interface {
	Sign(ctx context.Context, toolSlug, method, path, query, bodyHash string) (toolauth.Signature, error)
	SignDigestTrailer(ctx context.Context, toolSlug string, sig toolauth.Signature, digestValue string) (string, error)
}

var _ RequestSigner = (*toolauth.Signer)(nil)

// Gateway is the reverse proxy for tool services.
type Gateway struct {
	tools           ToolLookup
	client          *http.Client
	transport       *http.Transport
	maxBodyBytes    int64
	validate        func(rawURL string) error
	signer          RequestSigner
	signBufferBytes int64
	resolver        service.IPResolver
	policy          service.UpstreamIPPolicy
	allow           service.UpstreamAllowlist
	tokens          TokenValidator
	tokenLimiter    TokenRateLimiter
	ipResolver      *service.ClientIPResolver
}

// New builds a Gateway with a bounded, purpose-built transport.
func New(tools ToolLookup, opts Options) *Gateway {
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if opts.ConnectTimeout <= 0 {
		opts.ConnectTimeout = DefaultConnectTimeout
	}
	if opts.ResponseHeaderTimeout <= 0 {
		opts.ResponseHeaderTimeout = DefaultResponseHeaderTimeout
	}
	if opts.IdleConnTimeout <= 0 {
		opts.IdleConnTimeout = DefaultIdleConnTimeout
	}

	resolver := opts.Resolver
	if resolver == nil {
		resolver = service.SystemResolver()
	}
	policy := opts.IPPolicy
	if !policy.IsConfigured() {
		policy = service.DefaultUpstreamIPPolicy()
	}

	dialer := &pinnedDialer{
		resolver: resolver,
		policy:   policy,
		allow:    opts.UpstreamAllowlist,
		dialer: &net.Dialer{
			Timeout:   opts.ConnectTimeout,
			KeepAlive: 30 * time.Second,
		},
	}

	var tlsConfig *tls.Config
	if opts.TLSRootCAs != nil {
		tlsConfig = &tls.Config{
			RootCAs:    opts.TLSRootCAs,
			MinVersion: tls.VersionTLS12,
		}
	}

	transport := &http.Transport{
		// No environment proxy: forwarded requests only ever go to internal
		// services resolved from the registry.
		Proxy: nil,
		// The dialer pins the validated IP; it never re-resolves the hostname.
		DialContext:           dialer.DialContext,
		TLSClientConfig:       tlsConfig,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          DefaultMaxIdleConns,
		MaxIdleConnsPerHost:   DefaultMaxIdleConnsPerHost,
		IdleConnTimeout:       opts.IdleConnTimeout,
		TLSHandshakeTimeout:   DefaultTLSHandshakeTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: opts.ResponseHeaderTimeout,
		// Tool responses are forwarded as produced; re-compressing them would
		// require buffering and would change Content-Length semantics.
		DisableCompression: true,
	}

	validate := opts.UpstreamValidator
	if validate == nil {
		allow := opts.UpstreamAllowlist
		validate = func(raw string) error {
			return service.ValidateUpstream(raw, allow)
		}
	}

	signBufferBytes := opts.SignBufferBytes
	if signBufferBytes <= 0 {
		signBufferBytes = DefaultSignBufferBytes
	}

	return &Gateway{
		tools:           tools,
		transport:       transport,
		maxBodyBytes:    opts.MaxBodyBytes,
		validate:        validate,
		signer:          opts.Signer,
		signBufferBytes: signBufferBytes,
		resolver:        resolver,
		policy:          policy,
		allow:           opts.UpstreamAllowlist,
		tokens:          opts.TokenValidator,
		tokenLimiter:    opts.TokenRateLimiter,
		ipResolver:      opts.ClientIPResolver,
		client: &http.Client{
			Transport: transport,
			// Never follow upstream redirects automatically. A redirect Core has
			// not validated is never forwarded either (see authorizeRedirectTarget),
			// which prevents Core or the browser from being steered to a host that
			// bypassed the upstream policy.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Close releases idle upstream connections.
func (g *Gateway) Close() {
	if g.transport != nil {
		g.transport.CloseIdleConnections()
	}
}

// Serve proxies a /t/{slug}/... request to the tool's configured upstream.
func (g *Gateway) Serve(c *gin.Context) {
	ctx := c.Request.Context()

	slug := c.Param("slug")
	if !slugPattern.MatchString(slug) {
		writeError(c, http.StatusNotFound, "tool not found")
		return
	}

	tool, err := g.tools.GetBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, service.ErrToolNotFound) {
			writeError(c, http.StatusNotFound, "tool not found")
			return
		}
		// Repository/driver errors can contain connection details; the client
		// gets a generic message and nothing else.
		writeError(c, http.StatusInternalServerError, "internal error")
		return
	}
	if tool == nil || tool.DeletedAt != nil {
		writeError(c, http.StatusNotFound, "tool not found")
		return
	}

	switch tool.Status {
	case model.ToolStatusActive:
		// routable
	case model.ToolStatusMaintenance:
		notice := "Tool sedang dalam pemeliharaan. Silakan coba lagi nanti."
		if tool.MaintenanceMessage != nil {
			if msg := strings.TrimSpace(*tool.MaintenanceMessage); msg != "" {
				notice = msg
			}
		}
		writeError(c, http.StatusServiceUnavailable, notice)
		return
	case model.ToolStatusDisabled:
		writeError(c, http.StatusForbidden, "tool access is disabled")
		return
	default:
		// draft, or an unrecognized value: unpublished tools are not routable.
		writeError(c, http.StatusNotFound, "tool not found")
		return
	}

	switch tool.AccessType {
	case model.ToolAccessPublic:
		// no token required
	case model.ToolAccessToken:
		if !g.authorizeToken(c, tool) {
			return
		}
	default:
		writeError(c, http.StatusForbidden, "tool access denied")
		return
	}

	if g.validate != nil {
		if err := g.validate(tool.UpstreamURL); err != nil {
			// Do not echo the reason: it would give SSRF probing feedback.
			writeError(c, http.StatusBadGateway, "tool upstream is unavailable")
			return
		}
	}

	escapedPath := c.Request.URL.EscapedPath()
	prefix := "/t/" + slug
	if !strings.HasPrefix(escapedPath, prefix) {
		writeError(c, http.StatusNotFound, "tool not found")
		return
	}

	target, err := buildTargetURL(tool.UpstreamURL, escapedPath[len(prefix):], c.Request.URL.RawQuery)
	if err != nil {
		writeError(c, http.StatusBadGateway, "tool upstream is unavailable")
		return
	}

	outReq, err := http.NewRequestWithContext(ctx, c.Request.Method, target.String(), c.Request.Body)
	if err != nil {
		writeError(c, http.StatusBadGateway, "tool upstream is unavailable")
		return
	}
	// Preserve the exact body semantics, including unknown-length (chunked)
	// uploads, which NewRequest cannot infer from a generic io.Reader.
	outReq.ContentLength = c.Request.ContentLength
	outReq.Host = target.Host
	outReq.Header = c.Request.Header.Clone()
	sanitizeRequestHeaders(outReq.Header)
	setForwardedHeaders(outReq, c, tool, g.ipResolver)

	if g.maxBodyBytes > 0 {
		if c.Request.ContentLength > g.maxBodyBytes {
			writeError(c, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		if outReq.Body != nil && outReq.Body != http.NoBody {
			outReq.Body = &limitedBody{rc: outReq.Body, remaining: g.maxBodyBytes}
		}
	}

	// Every forwarded request is signed with the tool's own key so the tool can
	// prove it came from Core (docs/architecture.md §4.4). Signing failures fail
	// closed: an unsigned request must never reach a tool.
	if g.signer != nil {
		if err := g.signRequest(ctx, outReq, tool); err != nil {
			if errors.Is(err, errBodyTooLarge) {
				writeError(c, http.StatusRequestEntityTooLarge, "request body too large")
				return
			}
			writeError(c, http.StatusBadGateway, "tool upstream is unavailable")
			return
		}
	}

	resp, err := g.client.Do(outReq)
	if err != nil {
		switch {
		case errors.Is(err, errBodyTooLarge):
			writeError(c, http.StatusRequestEntityTooLarge, "request body too large")
		case ctx.Err() != nil:
			// The client disconnected; there is nobody to answer.
			c.Abort()
		case isTimeout(err):
			writeError(c, http.StatusGatewayTimeout, "tool upstream timed out")
		default:
			writeError(c, http.StatusBadGateway, "tool upstream is unavailable")
		}
		return
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	// A redirect is never followed, and it is only passed to the client when its
	// target satisfies the same upstream policy (allowlist, scheme, port, DNS and
	// the pinned-address policy). Anything else is answered as a gateway error so
	// an unvalidated target can never be reached through Core.
	if isRedirectStatus(resp.StatusCode) {
		if err := g.authorizeRedirectTarget(ctx, resp.Header.Get("Location")); err != nil {
			writeError(c, http.StatusBadGateway, "tool upstream returned an unvalidated redirect")
			return
		}
	}

	copyResponseHeaders(c.Writer.Header(), resp.Header)
	c.Status(resp.StatusCode)
	_ = flushCopy(c.Writer, resp.Body)
}

// authorizeToken enforces access=token. The token must be presented in the
// Authorization header ("Bearer <token>"); a token in the query string is
// ignored, never accepted, and never logged. Every failure returns the same
// generic 401 so a caller cannot tell "missing" from "unknown" from "expired"
// from "revoked" from "belongs to another tool".
//
// It returns true when the request may proceed.
func (g *Gateway) authorizeToken(c *gin.Context, tool *model.Tool) bool {
	if g.tokens == nil {
		// Fail closed: without a validator, a token tool must not become public.
		writeError(c, http.StatusUnauthorized, "this tool requires an access token")
		return false
	}

	// Throttle per source address before doing any hashing or storage work, so
	// online guessing is bounded. A nil limiter means throttling is disabled
	// (tests only).
	if g.tokenLimiter != nil && !g.tokenLimiter.Allow("tool-token:"+g.clientAddr(c.Request)) {
		c.Header("Retry-After", "60")
		writeError(c, http.StatusTooManyRequests, "too many token attempts")
		return false
	}

	plaintext, ok := bearerToken(c.Request.Header.Get("Authorization"))
	if !ok {
		writeError(c, http.StatusUnauthorized, "invalid or missing access token")
		return false
	}

	token, err := g.tokens.Validate(c.Request.Context(), plaintext, tool.ID, time.Now())
	if err != nil || token == nil {
		// Never echo the error: it could distinguish failure causes.
		writeError(c, http.StatusUnauthorized, "invalid or missing access token")
		return false
	}

	// Record usage best-effort without blocking the request.
	g.tokens.TouchLastUsed(context.WithoutCancel(c.Request.Context()), token.ID, time.Now())
	return true
}

// bearerToken extracts the token from an "Authorization: Bearer <token>" value.
// It is case-insensitive on the scheme and rejects any other scheme.
func bearerToken(header string) (string, bool) {
	const scheme = "bearer "
	header = strings.TrimSpace(header)
	if len(header) <= len(scheme) {
		return "", false
	}
	if !strings.EqualFold(header[:len(scheme)], scheme) {
		return "", false
	}
	token := strings.TrimSpace(header[len(scheme):])
	if token == "" {
		return "", false
	}
	return token, true
}

// signRequest signs the outbound request with the tool's key.
//
// Bodies whose length is known and small are buffered so the signature covers
// the real body hash. Larger or unknown-length bodies are streamed: the header
// signature covers a marker and the digest of the bytes actually forwarded is
// bound by a signed trailer, so nothing is buffered and integrity is still
// covered by the signature. If integrity cannot be guaranteed the request is
// rejected instead of being forwarded unsigned.
func (g *Gateway) signRequest(ctx context.Context, outReq *http.Request, tool *model.Tool) error {
	path := outReq.URL.EscapedPath()
	query := outReq.URL.RawQuery

	if outReq.Body == nil || outReq.Body == http.NoBody {
		sig, err := g.signer.Sign(ctx, tool.Slug, outReq.Method, path, query, toolauth.EmptyBodySHA256)
		if err != nil {
			return err
		}
		sig.Apply(outReq.Header)
		return nil
	}

	if outReq.ContentLength >= 0 && outReq.ContentLength <= g.signBufferBytes {
		raw, err := io.ReadAll(io.LimitReader(outReq.Body, g.signBufferBytes+1))
		if err != nil {
			return err
		}
		if int64(len(raw)) > g.signBufferBytes {
			return errBodyTooLarge
		}
		_ = outReq.Body.Close()
		outReq.Body = io.NopCloser(bytes.NewReader(raw))
		outReq.ContentLength = int64(len(raw))

		sig, err := g.signer.Sign(ctx, tool.Slug, outReq.Method, path, query, toolauth.BodyHash(raw))
		if err != nil {
			return err
		}
		sig.Apply(outReq.Header)
		return nil
	}

	// Streamed body: the hash is only known at EOF, so bind it with a trailer
	// signature over the same nonce/timestamp-bearing canonical string.
	sig, err := g.signer.Sign(ctx, tool.Slug, outReq.Method, path, query, toolauth.BodyHashStreamed)
	if err != nil {
		return err
	}
	outReq.ContentLength = -1
	outReq.TransferEncoding = []string{"chunked"}
	outReq.Trailer = http.Header{
		toolauth.HeaderBodyDigest:    nil,
		toolauth.HeaderBodySignature: nil,
	}
	trailer := outReq.Trailer
	outReq.Body = &signingBody{
		rc: outReq.Body,
		onEOF: func(bodyHash string) error {
			digest := "sha-256=" + bodyHash
			value, err := g.signer.SignDigestTrailer(ctx, tool.Slug, sig, digest)
			if err != nil {
				return err
			}
			trailer.Set(toolauth.HeaderBodyDigest, digest)
			trailer.Set(toolauth.HeaderBodySignature, value)
			return nil
		},
	}
	sig.Apply(outReq.Header)
	return nil
}

// signingBody hashes the bytes as they are forwarded and, at EOF, records the
// signed digest trailer for the request.
type signingBody struct {
	rc    io.ReadCloser
	hash  hash.Hash
	onEOF func(bodyHash string) error
	done  bool
}

func (b *signingBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	if n > 0 {
		if b.hash == nil {
			b.hash = sha256.New()
		}
		b.hash.Write(p[:n])
	}
	if err == io.EOF && !b.done {
		b.done = true
		if b.hash == nil {
			b.hash = sha256.New()
		}
		if cbErr := b.onEOF(hex.EncodeToString(b.hash.Sum(nil))); cbErr != nil {
			return n, cbErr
		}
	}
	return n, err
}

func (b *signingBody) Close() error { return b.rc.Close() }

// isRedirectStatus reports whether a status code carries a redirect the client
// could follow.
func isRedirectStatus(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

// authorizeRedirectTarget re-applies the whole upstream policy to a redirect
// target before Core forwards it to the client.
//
// A relative target stays on the already validated upstream and is allowed. An
// absolute target must pass the URL policy (scheme, port, host allowlist or
// permitted address class) and must resolve to addresses the IP policy permits,
// with the same fail-closed behaviour as a first-hop connection.
func (g *Gateway) authorizeRedirectTarget(ctx context.Context, raw string) error {
	location := strings.TrimSpace(raw)
	if location == "" {
		return nil
	}

	target, err := url.Parse(location)
	if err != nil {
		return fmt.Errorf("%w: redirect location is not a valid URL", service.ErrInvalidUpstream)
	}
	if target.Host == "" {
		// Relative redirect: same upstream Core already validated.
		return nil
	}

	if err := g.validate(location); err != nil {
		return err
	}

	host := target.Hostname()
	if net.ParseIP(host) == nil && !g.allow.Contains(host) {
		return fmt.Errorf("%w: redirect host %q is not in the allowed upstream list", service.ErrInvalidUpstream, host)
	}

	if _, err := service.ResolveAllowedUpstream(ctx, g.resolver, host, g.policy); err != nil {
		return err
	}
	return nil
}

// buildTargetURL joins the tool's upstream base URL with the path remainder
// (which still carries the client's original percent-encoding).
func buildTargetURL(rawUpstream, rest, rawQuery string) (*url.URL, error) {
	up, err := url.Parse(strings.TrimSpace(rawUpstream))
	if err != nil {
		return nil, err
	}
	if up.Scheme == "" || up.Host == "" {
		return nil, errors.New("gateway: upstream URL is missing scheme or host")
	}

	if rest == "" {
		rest = "/"
	}
	joined := strings.TrimSuffix(up.EscapedPath(), "/") + rest
	if !strings.HasPrefix(joined, "/") {
		joined = "/" + joined
	}

	target, err := url.Parse(up.Scheme + "://" + up.Host + joined)
	if err != nil {
		return nil, err
	}
	target.RawQuery = rawQuery
	return target, nil
}

// sanitizeRequestHeaders removes hop-by-hop headers (including those named by
// the incoming Connection header) and any client-supplied credential/identity
// header.
func sanitizeRequestHeaders(h http.Header) {
	for _, value := range h.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			if name = strings.TrimSpace(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
	for _, name := range strippedRequestHeaders {
		h.Del(name)
	}
}

// setForwardedHeaders injects the forwarding context the tool may log. Values
// are recomputed from the connection (or, behind a trusted proxy, from the
// validated forwarded chain), never inherited verbatim from the client.
func setForwardedHeaders(outReq *http.Request, c *gin.Context, tool *model.Tool, resolver *service.ClientIPResolver) {
	proto := "http"
	if c.Request.TLS != nil {
		proto = "https"
	}

	outReq.Header.Set("X-Forwarded-For", clientAddress(c.Request, resolver))
	outReq.Header.Set("X-Forwarded-Proto", proto)
	outReq.Header.Set("X-Forwarded-Host", c.Request.Host)
	outReq.Header.Set("X-Gateway", gatewayIdentifier)
	outReq.Header.Set("X-Tool-Slug", tool.Slug)
	outReq.Header.Set("X-Access-Type", tool.AccessType)
}

// copyResponseHeaders copies upstream headers, dropping hop-by-hop headers and
// any internal gateway header so they never reach the browser.
func copyResponseHeaders(dst, src http.Header) {
	for _, value := range src.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			if name = strings.TrimSpace(name); name != "" {
				src.Del(name)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		src.Del(name)
	}
	for _, name := range strippedResponseHeaders {
		src.Del(name)
	}
	for name, values := range src {
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}

// flushCopy streams src to dst, flushing after each chunk so the client sees
// data as the tool produces it.
func flushCopy(dst http.ResponseWriter, src io.Reader) error {
	flusher, canFlush := dst.(http.Flusher)
	buf := make([]byte, 32*1024)

	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr
			}
			if canFlush {
				flusher.Flush()
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// writeError sends a plain-text, non-cacheable error response. Messages are
// deliberately generic so internal topology and upstream details stay hidden.
func writeError(c *gin.Context, status int, message string) {
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.Header("X-Content-Type-Options", "nosniff")
	c.String(status, message)
}

// clientAddr returns the caller address for r using the gateway's configured
// resolver, or the TCP peer when no resolver is set.
func (g *Gateway) clientAddr(r *http.Request) string {
	return clientAddress(r, g.ipResolver)
}

// clientAddress derives the caller address for rate limiting and forwarding.
//
// With a configured resolver it honours X-Forwarded-For only for requests that
// arrive from a trusted proxy (a client-supplied header on a direct connection
// is discarded). With no resolver it falls back to the TCP peer address in
// RemoteAddr only, so any client can be identified without trusting a header it
// controls.
func clientAddress(r *http.Request, resolver *service.ClientIPResolver) string {
	if resolver != nil {
		return resolver.Resolve(r)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		if host != "" {
			return host
		}
	}
	return r.RemoteAddr
}

// isTimeout reports whether err is a deadline or network timeout.
func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// limitedBody enforces a byte cap while streaming a request body upstream.
// It never buffers: the limit is checked as bytes flow through.
type limitedBody struct {
	rc        io.ReadCloser
	remaining int64
}

func (b *limitedBody) Read(p []byte) (int, error) {
	if b.remaining < 0 {
		return 0, errBodyTooLarge
	}
	// Read at most one byte beyond the limit so exceeding it is detectable.
	if int64(len(p)) > b.remaining+1 {
		p = p[:b.remaining+1]
	}
	n, err := b.rc.Read(p)
	b.remaining -= int64(n)
	if b.remaining < 0 {
		return n, errBodyTooLarge
	}
	return n, err
}

func (b *limitedBody) Close() error { return b.rc.Close() }

// Ensure the concrete registry service satisfies the lookup contract.
var _ ToolLookup = (*service.ToolService)(nil)
