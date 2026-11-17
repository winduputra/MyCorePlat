// Package config loads and validates application configuration from
// environment variables. Secrets are never hardcoded; the loader fails fast
// when required values are missing or malformed.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Environment names understood by the application.
const (
	EnvDevelopment = "development"
	EnvProduction  = "production"
)

// Defaults for authentication-related settings. These are documented defaults,
// not secrets; secrets are never hardcoded.
const (
	defaultSessionTTL          = 12 * time.Hour
	defaultLoginRateLimit      = 5
	defaultLoginRateWindowMins = 15
	// defaultPreAuthCSRFTTL bounds how long a pre-auth (login) CSRF token stays
	// valid. It is capped at maxPreAuthCSRFTTL regardless of configuration.
	defaultPreAuthCSRFTTL = 10 * time.Minute
	// maxPreAuthCSRFTTL is the hard upper bound for the pre-auth CSRF token
	// lifetime. Tokens are short-lived by design; longer lifetimes widen the
	// replay window, so the value cannot be raised above this cap.
	maxPreAuthCSRFTTL = 10 * time.Minute
)

// Defaults for the gateway reverse proxy. These are documented defaults, not
// secrets.
const (
	// defaultGatewayMaxBodyBytes caps a forwarded request body at 25 MiB.
	defaultGatewayMaxBodyBytes int64 = 25 << 20
	// defaultGatewayConnectTimeout bounds dialing an upstream tool.
	defaultGatewayConnectTimeout = 5 * time.Second
	// defaultGatewayResponseHeaderTimeout bounds waiting for upstream headers.
	defaultGatewayResponseHeaderTimeout = 60 * time.Second
	// defaultGatewayIdleConnTimeout bounds idle upstream connections.
	defaultGatewayIdleConnTimeout = 90 * time.Second

	// defaultHMACSkew is the accepted clock-skew window for internal
	// Core -> Tool signatures (HMAC_SKEW).
	defaultHMACSkew = 60 * time.Second
	// defaultNonceTTL is how long a keyId+nonce pair is remembered for replay
	// protection (NONCE_TTL). It is never allowed below twice the skew window.
	defaultNonceTTL = 2 * time.Minute
	// defaultGatewaySignBufferBytes is the largest request body Core buffers in
	// memory so it can sign the exact bytes. Larger or unknown-length bodies are
	// streamed and bound by a signed digest trailer instead.
	defaultGatewaySignBufferBytes int64 = 1 << 20

	// defaultTokenDefaultTTL is the expiry applied to an access token when the
	// admin does not choose one (TOKEN_DEFAULT_TTL).
	defaultTokenDefaultTTL = 30 * 24 * time.Hour
	// defaultTokenMaxTTL is the longest expiry an access token may be given
	// (TOKEN_MAX_TTL).
	defaultTokenMaxTTL = 365 * 24 * time.Hour
	// defaultTokenRateLimit bounds token-validation attempts per source IP.
	defaultTokenRateLimit = 60
	// defaultTokenRateWindow is the sliding window for token validation.
	defaultTokenRateWindowMins = 1

	// defaultHealthInterval is the health-poll cadence per sweep
	// (HEALTHCHECK_INTERVAL). Conservative by design: probing every tool more
	// often than this adds load to every tool service.
	defaultHealthInterval = 30 * time.Second
	// defaultHealthTimeout bounds a single health probe (HEALTHCHECK_TIMEOUT).
	defaultHealthTimeout = 5 * time.Second
	// defaultHealthMaxConcurrent bounds how many health probes run at once
	// (HEALTHCHECK_MAX_CONCURRENT).
	defaultHealthMaxConcurrent = 5
	// defaultActivityMetadataLimit caps the byte size of a stored
	// activity_logs.metadata_json document (ACTIVITY_METADATA_LIMIT).
	defaultActivityMetadataLimit = 2048
	// maxActivityMetadataLimit keeps an operator from configuring an audit row
	// large enough to bloat the table or the admin listing.
	maxActivityMetadataLimit = 16384
)

// Config holds the runtime configuration for the Core application.
// Database settings were added in Task 4; admin-authentication settings in
// Task 5. Token and internal-auth settings are added in later, approved tasks.
type Config struct {
	// Environment is the deployment environment: "development" or "production".
	Environment string
	// HTTPAddr is the listen address for the HTTP server (e.g. ":8080").
	HTTPAddr string
	// ReadHeaderTimeoutSeconds bounds how long the server waits for request headers.
	ReadHeaderTimeoutSeconds int
	// DatabaseDSN is the resolved MariaDB DSN used by the application.
	// It is never logged. Resolved from DB_DSN_FILE (preferred) or DB_DSN.
	DatabaseDSN string

	// SessionTTL is the absolute lifetime of an admin session.
	SessionTTL time.Duration
	// CookieSecure controls the Secure flag on the session cookie. It defaults
	// to true in production and false in development, and can be overridden
	// via COOKIE_SECURE.
	CookieSecure bool
	// LoginRateLimit is the maximum number of failed login attempts allowed per
	// identity (IP and username) within LoginRateWindow.
	LoginRateLimit int
	// LoginRateWindow is the sliding window for login rate limiting.
	LoginRateWindow time.Duration

	// CSRFSecret is the server-side HMAC key used to sign pre-auth (login) CSRF
	// tokens. It is never logged and never hardcoded; resolved from
	// CSRF_SECRET_FILE (preferred) or CSRF_SECRET.
	CSRFSecret []byte
	// PreAuthCSRFTTL is the lifetime of a signed pre-auth CSRF token. It is
	// bounded to at most 10 minutes regardless of configuration.
	PreAuthCSRFTTL time.Duration

	// TrustedOrigin, when set, enables an Origin/Referer check on the login
	// POST as defense in depth. Empty disables the check (e.g. tests/dev).
	TrustedOrigin string

	// UpstreamAllowedHosts is the exact allowlist of internal service
	// hostnames that a tool's upstream URL may point at. It comes only from
	// server-side configuration (UPSTREAM_ALLOWED_HOSTS), never from client
	// input or a manifest. An empty list means no hostname is allowed.
	UpstreamAllowedHosts []string

	// UpstreamAllowedCIDRs is the server-side list of address ranges a resolved
	// upstream hostname or IP literal may fall into (UPSTREAM_ALLOWED_CIDRS).
	// Empty means the documented internal defaults are used. Loopback,
	// link-local, multicast, unspecified, reserved and metadata addresses are
	// always denied regardless of this list.
	UpstreamAllowedCIDRs []string

	// GatewayMaxBodyBytes caps the request body forwarded to a tool service.
	GatewayMaxBodyBytes int64
	// GatewayConnectTimeout bounds dialing an upstream tool.
	GatewayConnectTimeout time.Duration
	// GatewayResponseHeaderTimeout bounds waiting for upstream response headers.
	GatewayResponseHeaderTimeout time.Duration
	// GatewayIdleConnTimeout bounds idle upstream connections kept in the pool.
	GatewayIdleConnTimeout time.Duration

	// ToolHMACKeysDir is the directory holding one provisioned key file per tool
	// (<tool-slug>.json). Key material is never stored in the database, never in
	// a manifest, and never logged. An empty value disables request signing and
	// is rejected in production.
	ToolHMACKeysDir string
	// HMACSkew is the accepted clock-skew window for internal signatures.
	HMACSkew time.Duration
	// NonceTTL is how long a keyId+nonce pair is remembered. It must be at least
	// twice HMACSkew so a request cannot outlive its replay record.
	NonceTTL time.Duration
	// GatewaySignBufferBytes is the largest body buffered in memory to sign its
	// exact bytes; larger/unknown-length bodies use the signed digest trailer.
	GatewaySignBufferBytes int64

	// TokenDefaultTTL is the expiry applied to an access token when the admin
	// does not specify one.
	TokenDefaultTTL time.Duration
	// TokenMaxTTL is the longest expiry an access token may be given.
	TokenMaxTTL time.Duration
	// TokenRateLimit bounds tool access-token validation attempts per source IP
	// within TokenRateWindow. Zero disables the limiter.
	TokenRateLimit int
	// TokenRateWindow is the sliding window for token-validation rate limiting.
	TokenRateWindow time.Duration

	// HealthInterval is the cadence of a full health-check sweep. Zero
	// disables the background poller entirely.
	HealthInterval time.Duration
	// HealthTimeout bounds a single health probe.
	HealthTimeout time.Duration
	// HealthMaxConcurrent bounds how many probes run simultaneously.
	HealthMaxConcurrent int
	// ActivityMetadataLimit caps the stored activity_logs.metadata_json size in
	// bytes. Larger documents are replaced by a truncation marker.
	ActivityMetadataLimit int
}

// Load reads configuration from the environment and validates it.
// It returns an error describing the first problem found, so callers can
// fail fast at startup rather than serving with a broken configuration.
func Load() (*Config, error) {
	cfg := &Config{
		Environment:              getEnv("APP_ENV", EnvDevelopment),
		HTTPAddr:                 getEnv("HTTP_ADDR", ":8080"),
		ReadHeaderTimeoutSeconds: 10,
	}

	if v, ok := os.LookupEnv("HTTP_READ_HEADER_TIMEOUT_SECONDS"); ok && v != "" {
		seconds, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid HTTP_READ_HEADER_TIMEOUT_SECONDS %q: %w", v, err)
		}
		if seconds <= 0 {
			return nil, fmt.Errorf("HTTP_READ_HEADER_TIMEOUT_SECONDS must be positive, got %d", seconds)
		}
		cfg.ReadHeaderTimeoutSeconds = seconds
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	dsn, err := loadDatabaseDSN()
	if err != nil {
		return nil, err
	}
	cfg.DatabaseDSN = dsn

	if err := cfg.loadAuthSettings(); err != nil {
		return nil, err
	}

	secret, err := loadCSRFSecret()
	if err != nil {
		return nil, err
	}
	cfg.CSRFSecret = secret

	if err := cfg.loadGatewaySettings(); err != nil {
		return nil, err
	}

	if err := cfg.loadHMACSettings(); err != nil {
		return nil, err
	}

	if err := cfg.loadTokenSettings(); err != nil {
		return nil, err
	}

	if err := cfg.loadObservabilitySettings(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// loadObservabilitySettings resolves health-check and activity-log settings.
// Defaults are conservative: health polling is deliberately infrequent and
// audit metadata is deliberately small.
func (c *Config) loadObservabilitySettings() error {
	c.HealthInterval = defaultHealthInterval
	c.HealthTimeout = defaultHealthTimeout
	c.HealthMaxConcurrent = defaultHealthMaxConcurrent
	c.ActivityMetadataLimit = defaultActivityMetadataLimit

	if v := strings.TrimSpace(os.Getenv("HEALTHCHECK_INTERVAL")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("invalid HEALTHCHECK_INTERVAL %q: %w", v, err)
		}
		if d < 0 {
			return fmt.Errorf("HEALTHCHECK_INTERVAL must not be negative, got %s", v)
		}
		c.HealthInterval = d
	}

	if v := strings.TrimSpace(os.Getenv("HEALTHCHECK_TIMEOUT")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("invalid HEALTHCHECK_TIMEOUT %q: %w", v, err)
		}
		if d <= 0 {
			return fmt.Errorf("HEALTHCHECK_TIMEOUT must be positive, got %s", v)
		}
		c.HealthTimeout = d
	}

	if v := strings.TrimSpace(os.Getenv("HEALTHCHECK_MAX_CONCURRENT")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("invalid HEALTHCHECK_MAX_CONCURRENT %q: %w", v, err)
		}
		if n <= 0 {
			return fmt.Errorf("HEALTHCHECK_MAX_CONCURRENT must be positive, got %d", n)
		}
		c.HealthMaxConcurrent = n
	}

	if v := strings.TrimSpace(os.Getenv("ACTIVITY_METADATA_LIMIT")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("invalid ACTIVITY_METADATA_LIMIT %q: %w", v, err)
		}
		if n <= 0 {
			return fmt.Errorf("ACTIVITY_METADATA_LIMIT must be positive, got %d", n)
		}
		if n > maxActivityMetadataLimit {
			return fmt.Errorf("ACTIVITY_METADATA_LIMIT must not exceed %d, got %d", maxActivityMetadataLimit, n)
		}
		c.ActivityMetadataLimit = n
	}

	return nil
}

// loadTokenSettings resolves the access-token lifecycle settings.
func (c *Config) loadTokenSettings() error {
	c.TokenDefaultTTL = defaultTokenDefaultTTL
	if v := strings.TrimSpace(os.Getenv("TOKEN_DEFAULT_TTL")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("invalid TOKEN_DEFAULT_TTL %q: %w", v, err)
		}
		if d <= 0 {
			return fmt.Errorf("TOKEN_DEFAULT_TTL must be positive, got %s", d)
		}
		c.TokenDefaultTTL = d
	}

	c.TokenMaxTTL = defaultTokenMaxTTL
	if v := strings.TrimSpace(os.Getenv("TOKEN_MAX_TTL")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("invalid TOKEN_MAX_TTL %q: %w", v, err)
		}
		if d <= 0 {
			return fmt.Errorf("TOKEN_MAX_TTL must be positive, got %s", d)
		}
		c.TokenMaxTTL = d
	}
	if c.TokenMaxTTL < c.TokenDefaultTTL {
		return fmt.Errorf("TOKEN_MAX_TTL (%s) must not be shorter than TOKEN_DEFAULT_TTL (%s)", c.TokenMaxTTL, c.TokenDefaultTTL)
	}

	c.TokenRateLimit = defaultTokenRateLimit
	if v := strings.TrimSpace(os.Getenv("TOKEN_RATE_LIMIT")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("invalid TOKEN_RATE_LIMIT %q: %w", v, err)
		}
		if n < 0 {
			return fmt.Errorf("TOKEN_RATE_LIMIT must not be negative, got %d", n)
		}
		c.TokenRateLimit = n
	}

	c.TokenRateWindow = time.Duration(defaultTokenRateWindowMins) * time.Minute
	if v := strings.TrimSpace(os.Getenv("TOKEN_RATE_WINDOW")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("invalid TOKEN_RATE_WINDOW %q: %w", v, err)
		}
		if d <= 0 {
			return fmt.Errorf("TOKEN_RATE_WINDOW must be positive, got %s", d)
		}
		c.TokenRateWindow = d
	}

	return nil
}

// loadHMACSettings resolves the internal Core -> Tool request-signing settings.
//
// Signing keys themselves live in files under ToolHMACKeysDir; nothing secret is
// read or cached here. Signing may be left unconfigured in development, but
// production refuses to start without a key directory so unsigned requests to
// tools cannot be deployed by accident.
func (c *Config) loadHMACSettings() error {
	c.ToolHMACKeysDir = strings.TrimSpace(os.Getenv("TOOL_HMAC_KEYS_DIR"))

	c.HMACSkew = defaultHMACSkew
	if v, ok := os.LookupEnv("HMAC_SKEW"); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("invalid HMAC_SKEW %q: %w", v, err)
		}
		if d <= 0 {
			return fmt.Errorf("HMAC_SKEW must be positive, got %s", d)
		}
		c.HMACSkew = d
	}

	c.NonceTTL = defaultNonceTTL
	if v, ok := os.LookupEnv("NONCE_TTL"); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("invalid NONCE_TTL %q: %w", v, err)
		}
		if d <= 0 {
			return fmt.Errorf("NONCE_TTL must be positive, got %s", d)
		}
		c.NonceTTL = d
	}
	// The replay record must outlive the window in which a captured request is
	// still accepted, otherwise a replay could slip through after eviction.
	if minTTL := 2 * c.HMACSkew; c.NonceTTL < minTTL {
		return fmt.Errorf("NONCE_TTL must be at least twice HMAC_SKEW (%s), got %s", minTTL, c.NonceTTL)
	}

	c.GatewaySignBufferBytes = defaultGatewaySignBufferBytes
	if v, ok := os.LookupEnv("GATEWAY_SIGN_BUFFER_BYTES"); ok && v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid GATEWAY_SIGN_BUFFER_BYTES %q: %w", v, err)
		}
		if n <= 0 {
			return fmt.Errorf("GATEWAY_SIGN_BUFFER_BYTES must be positive, got %d", n)
		}
		c.GatewaySignBufferBytes = n
	}

	if c.IsProduction() && c.ToolHMACKeysDir == "" {
		return fmt.Errorf("TOOL_HMAC_KEYS_DIR must be set in production: tools reject unsigned requests")
	}

	return nil
}

// loadGatewaySettings resolves the reverse-proxy transport limits. Every value
// must be positive; malformed values fail fast at startup rather than falling
// back silently to a different limit.
func (c *Config) loadGatewaySettings() error {
	c.GatewayMaxBodyBytes = defaultGatewayMaxBodyBytes
	if v, ok := os.LookupEnv("GATEWAY_MAX_BODY_BYTES"); ok && v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid GATEWAY_MAX_BODY_BYTES %q: %w", v, err)
		}
		if n <= 0 {
			return fmt.Errorf("GATEWAY_MAX_BODY_BYTES must be positive, got %d", n)
		}
		c.GatewayMaxBodyBytes = n
	}

	c.GatewayConnectTimeout = defaultGatewayConnectTimeout
	if v, ok := os.LookupEnv("GATEWAY_CONNECT_TIMEOUT"); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("invalid GATEWAY_CONNECT_TIMEOUT %q: %w", v, err)
		}
		if d <= 0 {
			return fmt.Errorf("GATEWAY_CONNECT_TIMEOUT must be positive, got %q", v)
		}
		c.GatewayConnectTimeout = d
	}

	c.GatewayResponseHeaderTimeout = defaultGatewayResponseHeaderTimeout
	if v, ok := os.LookupEnv("GATEWAY_RESPONSE_HEADER_TIMEOUT"); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("invalid GATEWAY_RESPONSE_HEADER_TIMEOUT %q: %w", v, err)
		}
		if d <= 0 {
			return fmt.Errorf("GATEWAY_RESPONSE_HEADER_TIMEOUT must be positive, got %q", v)
		}
		c.GatewayResponseHeaderTimeout = d
	}

	c.GatewayIdleConnTimeout = defaultGatewayIdleConnTimeout
	if v, ok := os.LookupEnv("GATEWAY_IDLE_CONN_TIMEOUT"); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("invalid GATEWAY_IDLE_CONN_TIMEOUT %q: %w", v, err)
		}
		if d <= 0 {
			return fmt.Errorf("GATEWAY_IDLE_CONN_TIMEOUT must be positive, got %q", v)
		}
		c.GatewayIdleConnTimeout = d
	}

	return nil
}

// loadAuthSettings resolves session, cookie, and login rate-limit settings.
// Defaults are environment-aware: Secure cookies default on in production and
// off in development (so plain-HTTP local browsing works).
func (c *Config) loadAuthSettings() error {
	// Session TTL (duration string, e.g. "12h", "30m").
	c.SessionTTL = defaultSessionTTL
	if v, ok := os.LookupEnv("SESSION_TTL"); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("invalid SESSION_TTL %q: %w", v, err)
		}
		if d <= 0 {
			return fmt.Errorf("SESSION_TTL must be positive, got %q", v)
		}
		c.SessionTTL = d
	}

	// Cookie Secure flag: default by environment, overridable.
	c.CookieSecure = c.IsProduction()
	if v, ok := os.LookupEnv("COOKIE_SECURE"); ok && v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("invalid COOKIE_SECURE %q: %w", v, err)
		}
		c.CookieSecure = b
	}

	// Login rate limit (attempts per window).
	c.LoginRateLimit = defaultLoginRateLimit
	if v, ok := os.LookupEnv("LOGIN_RATE_LIMIT"); ok && v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("invalid LOGIN_RATE_LIMIT %q: %w", v, err)
		}
		if n <= 0 {
			return fmt.Errorf("LOGIN_RATE_LIMIT must be positive, got %d", n)
		}
		c.LoginRateLimit = n
	}

	// Login rate window (duration string).
	c.LoginRateWindow = time.Duration(defaultLoginRateWindowMins) * time.Minute
	if v, ok := os.LookupEnv("LOGIN_RATE_WINDOW"); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("invalid LOGIN_RATE_WINDOW %q: %w", v, err)
		}
		if d <= 0 {
			return fmt.Errorf("LOGIN_RATE_WINDOW must be positive, got %q", v)
		}
		c.LoginRateWindow = d
	}

	// Pre-auth CSRF token lifetime (duration string, capped at 10m).
	c.PreAuthCSRFTTL = defaultPreAuthCSRFTTL
	if v, ok := os.LookupEnv("PREAUTH_CSRF_TTL"); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("invalid PREAUTH_CSRF_TTL %q: %w", v, err)
		}
		if d <= 0 {
			return fmt.Errorf("PREAUTH_CSRF_TTL must be positive, got %q", v)
		}
		if d > maxPreAuthCSRFTTL {
			return fmt.Errorf("PREAUTH_CSRF_TTL must not exceed %s, got %q", maxPreAuthCSRFTTL, v)
		}
		c.PreAuthCSRFTTL = d
	}

	// Trusted origin for the login POST Origin/Referer check. Optional: when
	// unset the check is disabled (useful for tests and local dev). In
	// production this should be set to the canonical site origin, e.g.
	// https://tools.bpbj.lampungprov.go.id.
	if v, ok := os.LookupEnv("TRUSTED_ORIGIN"); ok && v != "" {
		trimmed := strings.TrimRight(strings.TrimSpace(v), "/")
		if trimmed == "" {
			return fmt.Errorf("TRUSTED_ORIGIN must not be blank when set")
		}
		c.TrustedOrigin = trimmed
	}

	c.UpstreamAllowedHosts = parseHostList(os.Getenv("UPSTREAM_ALLOWED_HOSTS"))
	c.UpstreamAllowedCIDRs = parseHostList(os.Getenv("UPSTREAM_ALLOWED_CIDRS"))

	return nil
}

// parseHostList splits a comma-separated host list, trimming whitespace and
// dropping empty entries. Order is preserved. It performs no validation of the
// hostnames themselves; that is enforced when the allowlist is applied.
func parseHostList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	hosts := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			hosts = append(hosts, trimmed)
		}
	}
	return hosts
}

// loadCSRFSecret resolves the HMAC key used to sign pre-auth CSRF tokens.
//
// Precedence: CSRF_SECRET_FILE (read from disk) overrides CSRF_SECRET. There is
// no default and no generated fallback: an empty/missing value is a fail-fast
// startup error, because a predictable CSRF key would allow token forgery.
// File contents are never included in error messages.
func loadCSRFSecret() ([]byte, error) {
	if path, ok := os.LookupEnv("CSRF_SECRET_FILE"); ok && path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read CSRF_SECRET_FILE %q: %w", path, err)
		}
		secret := []byte(strings.TrimSpace(string(raw)))
		if len(secret) == 0 {
			return nil, fmt.Errorf("CSRF_SECRET_FILE %q is empty", path)
		}
		return secret, nil
	}

	if v, ok := os.LookupEnv("CSRF_SECRET"); ok && v != "" {
		return []byte(v), nil
	}

	return nil, fmt.Errorf("CSRF secret is not configured: set CSRF_SECRET_FILE or CSRF_SECRET")
}

// loadDatabaseDSN resolves the database DSN from configuration.
//
// Precedence: DB_DSN_FILE (read from disk) overrides DB_DSN. There is no
// default DSN — an empty/missing value is a fail-fast startup error so the
// application never silently connects with guessed credentials.
func loadDatabaseDSN() (string, error) {
	if path, ok := os.LookupEnv("DB_DSN_FILE"); ok && path != "" {
		// Read the DSN from the secret file. Errors are wrapped without
		// including file contents so secrets never leak into logs.
		raw, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read DB_DSN_FILE %q: %w", path, err)
		}
		dsn := strings.TrimSpace(string(raw))
		if dsn == "" {
			return "", fmt.Errorf("DB_DSN_FILE %q is empty", path)
		}
		return dsn, nil
	}

	if dsn, ok := os.LookupEnv("DB_DSN"); ok && dsn != "" {
		return dsn, nil
	}

	return "", fmt.Errorf("database DSN is not configured: set DB_DSN_FILE or DB_DSN")
}

// validate enforces invariants on the loaded configuration.
func (c *Config) validate() error {
	switch c.Environment {
	case EnvDevelopment, EnvProduction:
	default:
		return fmt.Errorf("APP_ENV must be %q or %q, got %q", EnvDevelopment, EnvProduction, c.Environment)
	}
	if c.HTTPAddr == "" {
		return fmt.Errorf("HTTP_ADDR must not be empty")
	}
	return nil
}

// IsProduction reports whether the config targets the production environment.
func (c *Config) IsProduction() bool {
	return c.Environment == EnvProduction
}

// getEnv returns the value of key or fallback when the variable is unset or empty.
func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}
