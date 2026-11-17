package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// setValidBaseEnv sets the minimum environment required for Load() to succeed,
// including a database DSN. Individual tests override specific variables.
func setValidBaseEnv(t *testing.T) {
	t.Helper()
	t.Setenv("APP_ENV", EnvDevelopment)
	t.Setenv("HTTP_ADDR", ":8080")
	t.Setenv("HTTP_READ_HEADER_TIMEOUT_SECONDS", "")
	t.Setenv("DB_DSN", "user:pass@tcp(127.0.0.1:3306)/mycoreplat")
	t.Setenv("DB_DSN_FILE", "")
	t.Setenv("SESSION_TTL", "")
	t.Setenv("COOKIE_SECURE", "")
	t.Setenv("LOGIN_RATE_LIMIT", "")
	t.Setenv("LOGIN_RATE_WINDOW", "")
	// A CSRF secret is mandatory; tests that need a specific value override it.
	t.Setenv("CSRF_SECRET", "test-csrf-secret-value")
	t.Setenv("CSRF_SECRET_FILE", "")
	t.Setenv("PREAUTH_CSRF_TTL", "")
	t.Setenv("TRUSTED_ORIGIN", "")
	t.Setenv("TRUSTED_PROXIES", "")
	t.Setenv("UPSTREAM_ALLOWED_HOSTS", "")
	t.Setenv("UPSTREAM_ALLOWED_CIDRS", "")
	t.Setenv("GATEWAY_MAX_BODY_BYTES", "")
	t.Setenv("GATEWAY_CONNECT_TIMEOUT", "")
	t.Setenv("GATEWAY_RESPONSE_HEADER_TIMEOUT", "")
	t.Setenv("GATEWAY_IDLE_CONN_TIMEOUT", "")
	t.Setenv("TOOL_HMAC_KEYS_DIR", "")
	t.Setenv("HMAC_SKEW", "")
	t.Setenv("NONCE_TTL", "")
	t.Setenv("GATEWAY_SIGN_BUFFER_BYTES", "")
	t.Setenv("TOKEN_DEFAULT_TTL", "")
	t.Setenv("TOKEN_MAX_TTL", "")
	t.Setenv("TOKEN_RATE_LIMIT", "")
	t.Setenv("TOKEN_RATE_WINDOW", "")
	t.Setenv("HEALTHCHECK_INTERVAL", "")
	t.Setenv("HEALTHCHECK_TIMEOUT", "")
	t.Setenv("HEALTHCHECK_MAX_CONCURRENT", "")
	t.Setenv("ACTIVITY_METADATA_LIMIT", "")
	t.Setenv("INSTALLER_BASE_URL", "")
	t.Setenv("INSTALLER_BASE_URL_FILE", "")
	t.Setenv("INSTALLER_TOKEN", "")
	t.Setenv("INSTALLER_TOKEN_FILE", "")
	t.Setenv("INSTALLER_MAX_UPLOAD_BYTES", "")
}

func TestLoadDefaults(t *testing.T) {
	setValidBaseEnv(t)
	t.Setenv("APP_ENV", "")
	t.Setenv("HTTP_ADDR", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	if cfg.Environment != EnvDevelopment {
		t.Errorf("Environment = %q, want %q", cfg.Environment, EnvDevelopment)
	}
	if cfg.HTTPAddr != ":8080" {
		t.Errorf("HTTPAddr = %q, want %q", cfg.HTTPAddr, ":8080")
	}
	if cfg.ReadHeaderTimeoutSeconds != 10 {
		t.Errorf("ReadHeaderTimeoutSeconds = %d, want 10", cfg.ReadHeaderTimeoutSeconds)
	}
}

func TestLoadFromEnv(t *testing.T) {
	setValidBaseEnv(t)
	t.Setenv("APP_ENV", EnvProduction)
	t.Setenv("HTTP_ADDR", ":9090")
	t.Setenv("HTTP_READ_HEADER_TIMEOUT_SECONDS", "20")
	// Production requires a signing key directory (tools reject unsigned requests).
	t.Setenv("TOOL_HMAC_KEYS_DIR", "/run/secrets/tool-hmac")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	if cfg.Environment != EnvProduction {
		t.Errorf("Environment = %q, want %q", cfg.Environment, EnvProduction)
	}
	if !cfg.IsProduction() {
		t.Error("IsProduction() = false, want true")
	}
	if cfg.HTTPAddr != ":9090" {
		t.Errorf("HTTPAddr = %q, want %q", cfg.HTTPAddr, ":9090")
	}
	if cfg.ReadHeaderTimeoutSeconds != 20 {
		t.Errorf("ReadHeaderTimeoutSeconds = %d, want 20", cfg.ReadHeaderTimeoutSeconds)
	}
}

func TestLoadInvalidEnvironment(t *testing.T) {
	setValidBaseEnv(t)
	t.Setenv("APP_ENV", "staging")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() expected error for invalid APP_ENV, got nil")
	}
}

func TestLoadInvalidTimeout(t *testing.T) {
	setValidBaseEnv(t)
	t.Setenv("HTTP_READ_HEADER_TIMEOUT_SECONDS", "not-a-number")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() expected error for non-numeric timeout, got nil")
	}
}

func TestLoadNonPositiveTimeout(t *testing.T) {
	setValidBaseEnv(t)
	t.Setenv("HTTP_READ_HEADER_TIMEOUT_SECONDS", "0")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() expected error for non-positive timeout, got nil")
	}
}

func TestLoadDatabaseDSNFromEnv(t *testing.T) {
	setValidBaseEnv(t)
	want := "app:secret@tcp(db:3306)/mycoreplat?parseTime=true"
	t.Setenv("DB_DSN", want)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	if cfg.DatabaseDSN != want {
		t.Errorf("DatabaseDSN = %q, want %q", cfg.DatabaseDSN, want)
	}
}

func TestLoadDatabaseDSNFromFileTakesPrecedence(t *testing.T) {
	setValidBaseEnv(t)
	// DB_DSN is set to a different value; DB_DSN_FILE must win.
	t.Setenv("DB_DSN", "ignored@tcp(localhost:3306)/ignored")
	want := "fileuser:filepass@tcp(127.0.0.1:3306)/mycoreplat?parseTime=true"

	dir := t.TempDir()
	path := filepath.Join(dir, "db_dsn.txt")
	// Include surrounding whitespace/newline to prove trimming works.
	if err := os.WriteFile(path, []byte("  "+want+"\n"), 0o600); err != nil {
		t.Fatalf("write DSN file: %v", err)
	}
	t.Setenv("DB_DSN_FILE", path)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	if cfg.DatabaseDSN != want {
		t.Errorf("DatabaseDSN = %q, want %q (file must take precedence and be trimmed)", cfg.DatabaseDSN, want)
	}
}

func TestLoadDatabaseDSNMissingFailsFast(t *testing.T) {
	t.Setenv("APP_ENV", EnvDevelopment)
	t.Setenv("DB_DSN", "")
	t.Setenv("DB_DSN_FILE", "")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() expected error when no DSN configured, got nil")
	}
}

func TestLoadDatabaseDSNFileMissingFailsFast(t *testing.T) {
	setValidBaseEnv(t)
	t.Setenv("DB_DSN_FILE", filepath.Join(t.TempDir(), "does-not-exist.txt"))

	_, err := Load()
	if err == nil {
		t.Fatal("Load() expected error when DB_DSN_FILE path is unreadable, got nil")
	}
}

func TestLoadDatabaseDSNFileEmptyFailsFast(t *testing.T) {
	setValidBaseEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(path, []byte("   \n"), 0o600); err != nil {
		t.Fatalf("write empty DSN file: %v", err)
	}
	t.Setenv("DB_DSN_FILE", path)

	_, err := Load()
	if err == nil {
		t.Fatal("Load() expected error when DB_DSN_FILE is empty, got nil")
	}
}

func TestLoadAuthSettingsDefaults(t *testing.T) {
	setValidBaseEnv(t)
	t.Setenv("SESSION_TTL", "")
	t.Setenv("COOKIE_SECURE", "")
	t.Setenv("LOGIN_RATE_LIMIT", "")
	t.Setenv("LOGIN_RATE_WINDOW", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	if cfg.SessionTTL != 12*time.Hour {
		t.Errorf("SessionTTL = %v, want 12h", cfg.SessionTTL)
	}
	if cfg.CookieSecure {
		t.Error("CookieSecure = true in development, want false")
	}
	if cfg.LoginRateLimit != 5 {
		t.Errorf("LoginRateLimit = %d, want 5", cfg.LoginRateLimit)
	}
	if cfg.LoginRateWindow != 15*time.Minute {
		t.Errorf("LoginRateWindow = %v, want 15m", cfg.LoginRateWindow)
	}
}

func TestLoadAuthSettingsCookieSecureDefaultsTrueInProduction(t *testing.T) {
	setValidBaseEnv(t)
	t.Setenv("APP_ENV", EnvProduction)
	t.Setenv("COOKIE_SECURE", "")
	t.Setenv("TOOL_HMAC_KEYS_DIR", "/run/secrets/tool-hmac")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	if !cfg.CookieSecure {
		t.Error("CookieSecure = false in production, want true")
	}
}

func TestLoadAuthSettingsFromEnv(t *testing.T) {
	setValidBaseEnv(t)
	t.Setenv("SESSION_TTL", "30m")
	t.Setenv("COOKIE_SECURE", "true")
	t.Setenv("LOGIN_RATE_LIMIT", "10")
	t.Setenv("LOGIN_RATE_WINDOW", "5m")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	if cfg.SessionTTL != 30*time.Minute {
		t.Errorf("SessionTTL = %v, want 30m", cfg.SessionTTL)
	}
	if !cfg.CookieSecure {
		t.Error("CookieSecure = false, want true")
	}
	if cfg.LoginRateLimit != 10 {
		t.Errorf("LoginRateLimit = %d, want 10", cfg.LoginRateLimit)
	}
	if cfg.LoginRateWindow != 5*time.Minute {
		t.Errorf("LoginRateWindow = %v, want 5m", cfg.LoginRateWindow)
	}
}

func TestLoadAuthSettingsRejectsInvalid(t *testing.T) {
	cases := map[string]func(t *testing.T){
		"bad SESSION_TTL":       func(t *testing.T) { t.Setenv("SESSION_TTL", "not-a-duration") },
		"negative SESSION_TTL":  func(t *testing.T) { t.Setenv("SESSION_TTL", "-1h") },
		"bad COOKIE_SECURE":     func(t *testing.T) { t.Setenv("COOKIE_SECURE", "maybe") },
		"zero LOGIN_RATE_LIMIT": func(t *testing.T) { t.Setenv("LOGIN_RATE_LIMIT", "0") },
		"bad LOGIN_RATE_LIMIT":  func(t *testing.T) { t.Setenv("LOGIN_RATE_LIMIT", "abc") },
		"bad LOGIN_RATE_WINDOW": func(t *testing.T) { t.Setenv("LOGIN_RATE_WINDOW", "xyz") },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			setValidBaseEnv(t)
			setup(t)
			if _, err := Load(); err == nil {
				t.Fatalf("Load() expected error for %s, got nil", name)
			}
		})
	}
}

func TestLoadCSRFSecretFromEnv(t *testing.T) {
	setValidBaseEnv(t)
	t.Setenv("CSRF_SECRET", "env-csrf-secret")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	if string(cfg.CSRFSecret) != "env-csrf-secret" {
		t.Errorf("CSRFSecret = %q, want env value", cfg.CSRFSecret)
	}
}

func TestLoadCSRFSecretFromFileTakesPrecedence(t *testing.T) {
	setValidBaseEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "csrf_secret")
	if err := os.WriteFile(path, []byte("  file-csrf-secret\n"), 0o600); err != nil {
		t.Fatalf("write temp secret: %v", err)
	}
	t.Setenv("CSRF_SECRET_FILE", path)
	t.Setenv("CSRF_SECRET", "env-csrf-secret")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	if string(cfg.CSRFSecret) != "file-csrf-secret" {
		t.Errorf("CSRFSecret = %q, want trimmed file value (file takes precedence)", cfg.CSRFSecret)
	}
}

func TestLoadCSRFSecretMissingFailsFast(t *testing.T) {
	setValidBaseEnv(t)
	t.Setenv("CSRF_SECRET", "")
	t.Setenv("CSRF_SECRET_FILE", "")

	if _, err := Load(); err == nil {
		t.Fatal("Load() expected error when no CSRF secret is configured, got nil")
	}
}

func TestLoadCSRFSecretFileMissingFailsFast(t *testing.T) {
	setValidBaseEnv(t)
	t.Setenv("CSRF_SECRET_FILE", filepath.Join(t.TempDir(), "does-not-exist"))

	if _, err := Load(); err == nil {
		t.Fatal("Load() expected error when CSRF_SECRET_FILE does not exist, got nil")
	}
}

func TestLoadCSRFSecretFileEmptyFailsFast(t *testing.T) {
	setValidBaseEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "empty")
	if err := os.WriteFile(path, []byte("   \n"), 0o600); err != nil {
		t.Fatalf("write temp secret: %v", err)
	}
	t.Setenv("CSRF_SECRET_FILE", path)

	if _, err := Load(); err == nil {
		t.Fatal("Load() expected error when CSRF secret file is empty, got nil")
	}
}

func TestLoadPreAuthCSRFTTL(t *testing.T) {
	setValidBaseEnv(t)
	t.Setenv("PREAUTH_CSRF_TTL", "10m")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	if cfg.PreAuthCSRFTTL != 10*time.Minute {
		t.Errorf("PreAuthCSRFTTL = %v, want 10m", cfg.PreAuthCSRFTTL)
	}
}

func TestLoadPreAuthCSRFTTLDefault(t *testing.T) {
	setValidBaseEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	if cfg.PreAuthCSRFTTL != 10*time.Minute {
		t.Errorf("PreAuthCSRFTTL default = %v, want 10m", cfg.PreAuthCSRFTTL)
	}
}

func TestLoadPreAuthCSRFTTLRejectsInvalid(t *testing.T) {
	cases := map[string]string{
		"zero":     "0s",
		"negative": "-5m",
		"bad":      "soon",
		"tooLong":  "1h",
	}
	for name, val := range cases {
		t.Run(name, func(t *testing.T) {
			setValidBaseEnv(t)
			t.Setenv("PREAUTH_CSRF_TTL", val)
			if _, err := Load(); err == nil {
				t.Fatalf("Load() expected error for PREAUTH_CSRF_TTL=%q, got nil", val)
			}
		})
	}
}

func TestLoadTrustedOriginDefaultsEmpty(t *testing.T) {
	setValidBaseEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	if cfg.TrustedOrigin != "" {
		t.Errorf("TrustedOrigin default = %q, want empty", cfg.TrustedOrigin)
	}
}

func TestLoadTrustedOriginFromEnv(t *testing.T) {
	setValidBaseEnv(t)
	t.Setenv("TRUSTED_ORIGIN", "https://tools.bpbj.lampungprov.go.id/")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	if want := "https://tools.bpbj.lampungprov.go.id"; cfg.TrustedOrigin != want {
		t.Errorf("TrustedOrigin = %q, want %q", cfg.TrustedOrigin, want)
	}
}

func TestLoadTrustedOriginRejectsBlank(t *testing.T) {
	setValidBaseEnv(t)
	t.Setenv("TRUSTED_ORIGIN", "   ")
	if _, err := Load(); err == nil {
		t.Fatal("Load() expected error for blank TRUSTED_ORIGIN, got nil")
	}
}

func TestLoadUpstreamAllowedHostsDefaultsEmpty(t *testing.T) {
	setValidBaseEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	if len(cfg.UpstreamAllowedHosts) != 0 {
		t.Errorf("UpstreamAllowedHosts = %v, want empty", cfg.UpstreamAllowedHosts)
	}
	if len(cfg.UpstreamAllowedCIDRs) != 0 {
		t.Errorf("UpstreamAllowedCIDRs = %v, want empty (documented defaults apply)", cfg.UpstreamAllowedCIDRs)
	}
}

func TestLoadUpstreamAllowedCIDRsFromEnv(t *testing.T) {
	setValidBaseEnv(t)
	t.Setenv("UPSTREAM_ALLOWED_CIDRS", " 172.16.0.0/12 , 10.10.0.0/16 , ")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	want := []string{"172.16.0.0/12", "10.10.0.0/16"}
	if len(cfg.UpstreamAllowedCIDRs) != len(want) {
		t.Fatalf("UpstreamAllowedCIDRs = %v, want %v", cfg.UpstreamAllowedCIDRs, want)
	}
	for i := range want {
		if cfg.UpstreamAllowedCIDRs[i] != want[i] {
			t.Errorf("UpstreamAllowedCIDRs[%d] = %q, want %q", i, cfg.UpstreamAllowedCIDRs[i], want[i])
		}
	}
}

func TestLoadUpstreamAllowedHostsFromEnv(t *testing.T) {
	setValidBaseEnv(t)
	// Mixed whitespace and an empty trailing entry must be trimmed/dropped,
	// with order preserved.
	t.Setenv("UPSTREAM_ALLOWED_HOSTS", " image-compressor , backend-api ,,other-svc ")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	want := []string{"image-compressor", "backend-api", "other-svc"}
	if len(cfg.UpstreamAllowedHosts) != len(want) {
		t.Fatalf("UpstreamAllowedHosts = %v, want %v", cfg.UpstreamAllowedHosts, want)
	}
	for i := range want {
		if cfg.UpstreamAllowedHosts[i] != want[i] {
			t.Errorf("UpstreamAllowedHosts[%d] = %q, want %q", i, cfg.UpstreamAllowedHosts[i], want[i])
		}
	}
}

func TestParseHostList(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"blank", "   ", nil},
		{"single", "svc", []string{"svc"}},
		{"trims_and_drops_blanks", " a , b ,, c ", []string{"a", "b", "c"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseHostList(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("parseHostList(%q) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("parseHostList(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestLoadGatewaySettingsDefaults(t *testing.T) {
	setValidBaseEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	if cfg.GatewayMaxBodyBytes != 25<<20 {
		t.Errorf("GatewayMaxBodyBytes = %d, want %d", cfg.GatewayMaxBodyBytes, int64(25<<20))
	}
	if cfg.GatewayConnectTimeout != 5*time.Second {
		t.Errorf("GatewayConnectTimeout = %v, want 5s", cfg.GatewayConnectTimeout)
	}
	if cfg.GatewayResponseHeaderTimeout != 60*time.Second {
		t.Errorf("GatewayResponseHeaderTimeout = %v, want 60s", cfg.GatewayResponseHeaderTimeout)
	}
	if cfg.GatewayIdleConnTimeout != 90*time.Second {
		t.Errorf("GatewayIdleConnTimeout = %v, want 90s", cfg.GatewayIdleConnTimeout)
	}
}

func TestLoadGatewaySettingsFromEnv(t *testing.T) {
	setValidBaseEnv(t)
	t.Setenv("GATEWAY_MAX_BODY_BYTES", "1048576")
	t.Setenv("GATEWAY_CONNECT_TIMEOUT", "2s")
	t.Setenv("GATEWAY_RESPONSE_HEADER_TIMEOUT", "15s")
	t.Setenv("GATEWAY_IDLE_CONN_TIMEOUT", "45s")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	if cfg.GatewayMaxBodyBytes != 1048576 {
		t.Errorf("GatewayMaxBodyBytes = %d, want 1048576", cfg.GatewayMaxBodyBytes)
	}
	if cfg.GatewayConnectTimeout != 2*time.Second {
		t.Errorf("GatewayConnectTimeout = %v, want 2s", cfg.GatewayConnectTimeout)
	}
	if cfg.GatewayResponseHeaderTimeout != 15*time.Second {
		t.Errorf("GatewayResponseHeaderTimeout = %v, want 15s", cfg.GatewayResponseHeaderTimeout)
	}
	if cfg.GatewayIdleConnTimeout != 45*time.Second {
		t.Errorf("GatewayIdleConnTimeout = %v, want 45s", cfg.GatewayIdleConnTimeout)
	}
}

func TestLoadGatewaySettingsRejectsInvalid(t *testing.T) {
	cases := []struct {
		name string
		key  string
		val  string
	}{
		{"non_numeric_max_body", "GATEWAY_MAX_BODY_BYTES", "huge"},
		{"zero_max_body", "GATEWAY_MAX_BODY_BYTES", "0"},
		{"negative_max_body", "GATEWAY_MAX_BODY_BYTES", "-1"},
		{"bad_connect_timeout", "GATEWAY_CONNECT_TIMEOUT", "soon"},
		{"zero_connect_timeout", "GATEWAY_CONNECT_TIMEOUT", "0s"},
		{"bad_response_header_timeout", "GATEWAY_RESPONSE_HEADER_TIMEOUT", "later"},
		{"negative_idle_conn_timeout", "GATEWAY_IDLE_CONN_TIMEOUT", "-5s"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setValidBaseEnv(t)
			t.Setenv(tc.key, tc.val)
			if _, err := Load(); err == nil {
				t.Fatalf("Load() expected error for %s=%q, got nil", tc.key, tc.val)
			}
		})
	}
}

func TestLoadHMACSettingsDefaults(t *testing.T) {
	setValidBaseEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.ToolHMACKeysDir != "" {
		t.Errorf("ToolHMACKeysDir = %q, want empty in development default", cfg.ToolHMACKeysDir)
	}
	if cfg.HMACSkew != 60*time.Second {
		t.Errorf("HMACSkew = %s, want 60s", cfg.HMACSkew)
	}
	if cfg.NonceTTL != 2*time.Minute {
		t.Errorf("NonceTTL = %s, want 2m", cfg.NonceTTL)
	}
	if cfg.GatewaySignBufferBytes != 1<<20 {
		t.Errorf("GatewaySignBufferBytes = %d, want %d", cfg.GatewaySignBufferBytes, 1<<20)
	}
}

func TestLoadHMACSettingsFromEnv(t *testing.T) {
	setValidBaseEnv(t)
	t.Setenv("TOOL_HMAC_KEYS_DIR", "  /run/secrets/tool-hmac  ")
	t.Setenv("HMAC_SKEW", "30s")
	t.Setenv("NONCE_TTL", "90s")
	t.Setenv("GATEWAY_SIGN_BUFFER_BYTES", "4096")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.ToolHMACKeysDir != "/run/secrets/tool-hmac" {
		t.Errorf("ToolHMACKeysDir = %q, want trimmed path", cfg.ToolHMACKeysDir)
	}
	if cfg.HMACSkew != 30*time.Second {
		t.Errorf("HMACSkew = %s, want 30s", cfg.HMACSkew)
	}
	if cfg.NonceTTL != 90*time.Second {
		t.Errorf("NonceTTL = %s, want 90s", cfg.NonceTTL)
	}
	if cfg.GatewaySignBufferBytes != 4096 {
		t.Errorf("GatewaySignBufferBytes = %d, want 4096", cfg.GatewaySignBufferBytes)
	}
}

func TestLoadHMACSettingsRejectsInvalid(t *testing.T) {
	cases := []struct {
		name  string
		key   string
		value string
	}{
		{"bad_skew", "HMAC_SKEW", "soon"},
		{"zero_skew", "HMAC_SKEW", "0s"},
		{"negative_skew", "HMAC_SKEW", "-10s"},
		{"bad_nonce_ttl", "NONCE_TTL", "later"},
		{"zero_nonce_ttl", "NONCE_TTL", "0s"},
		{"nonce_ttl_shorter_than_two_skews", "NONCE_TTL", "90s"},
		{"bad_sign_buffer", "GATEWAY_SIGN_BUFFER_BYTES", "lots"},
		{"zero_sign_buffer", "GATEWAY_SIGN_BUFFER_BYTES", "0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setValidBaseEnv(t)
			t.Setenv(tc.key, tc.value)
			if _, err := Load(); err == nil {
				t.Fatalf("Load() expected error for %s=%q, got nil", tc.key, tc.value)
			}
		})
	}
}

func TestLoadHMACSettingsRequiresKeysDirInProduction(t *testing.T) {
	setValidBaseEnv(t)
	t.Setenv("APP_ENV", EnvProduction)
	t.Setenv("COOKIE_SECURE", "true")

	if _, err := Load(); err == nil {
		t.Fatal("Load() in production without TOOL_HMAC_KEYS_DIR should fail")
	}

	setValidBaseEnv(t)
	t.Setenv("APP_ENV", EnvProduction)
	t.Setenv("COOKIE_SECURE", "true")
	t.Setenv("TOOL_HMAC_KEYS_DIR", "/run/secrets/tool-hmac")
	if _, err := Load(); err != nil {
		t.Fatalf("Load() in production with keys dir error: %v", err)
	}
}

func TestLoadTokenSettingsDefaults(t *testing.T) {
	setValidBaseEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.TokenDefaultTTL != 30*24*time.Hour {
		t.Errorf("TokenDefaultTTL = %s, want 720h", cfg.TokenDefaultTTL)
	}
	if cfg.TokenMaxTTL != 365*24*time.Hour {
		t.Errorf("TokenMaxTTL = %s, want 8760h", cfg.TokenMaxTTL)
	}
	if cfg.TokenRateLimit != 60 {
		t.Errorf("TokenRateLimit = %d, want 60", cfg.TokenRateLimit)
	}
	if cfg.TokenRateWindow != time.Minute {
		t.Errorf("TokenRateWindow = %s, want 1m", cfg.TokenRateWindow)
	}
}

func TestLoadTokenSettingsFromEnv(t *testing.T) {
	setValidBaseEnv(t)
	t.Setenv("TOKEN_DEFAULT_TTL", "48h")
	t.Setenv("TOKEN_MAX_TTL", "720h")
	t.Setenv("TOKEN_RATE_LIMIT", "10")
	t.Setenv("TOKEN_RATE_WINDOW", "30s")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.TokenDefaultTTL != 48*time.Hour {
		t.Errorf("TokenDefaultTTL = %s, want 48h", cfg.TokenDefaultTTL)
	}
	if cfg.TokenMaxTTL != 720*time.Hour {
		t.Errorf("TokenMaxTTL = %s, want 720h", cfg.TokenMaxTTL)
	}
	if cfg.TokenRateLimit != 10 {
		t.Errorf("TokenRateLimit = %d, want 10", cfg.TokenRateLimit)
	}
	if cfg.TokenRateWindow != 30*time.Second {
		t.Errorf("TokenRateWindow = %s, want 30s", cfg.TokenRateWindow)
	}
}

func TestLoadTokenSettingsRejectsInvalid(t *testing.T) {
	cases := []struct {
		name  string
		key   string
		value string
	}{
		{"bad_default_ttl", "TOKEN_DEFAULT_TTL", "soon"},
		{"zero_default_ttl", "TOKEN_DEFAULT_TTL", "0"},
		{"bad_max_ttl", "TOKEN_MAX_TTL", "forever"},
		{"zero_max_ttl", "TOKEN_MAX_TTL", "0"},
		{"bad_rate_limit", "TOKEN_RATE_LIMIT", "lots"},
		{"negative_rate_limit", "TOKEN_RATE_LIMIT", "-1"},
		{"bad_rate_window", "TOKEN_RATE_WINDOW", "often"},
		{"zero_rate_window", "TOKEN_RATE_WINDOW", "0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setValidBaseEnv(t)
			t.Setenv(tc.key, tc.value)
			if _, err := Load(); err == nil {
				t.Fatalf("Load() with %s=%q should fail", tc.key, tc.value)
			}
		})
	}
}

func TestLoadTokenSettingsRejectsMaxShorterThanDefault(t *testing.T) {
	setValidBaseEnv(t)
	t.Setenv("TOKEN_DEFAULT_TTL", "100h")
	t.Setenv("TOKEN_MAX_TTL", "48h")
	if _, err := Load(); err == nil {
		t.Fatal("Load() with TOKEN_MAX_TTL shorter than TOKEN_DEFAULT_TTL should fail")
	}
}

func TestLoadObservabilitySettingsDefaults(t *testing.T) {
	setValidBaseEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HealthInterval != 30*time.Second {
		t.Fatalf("HealthInterval = %s, want 30s", cfg.HealthInterval)
	}
	if cfg.HealthTimeout != 5*time.Second {
		t.Fatalf("HealthTimeout = %s, want 5s", cfg.HealthTimeout)
	}
	if cfg.HealthMaxConcurrent != 5 {
		t.Fatalf("HealthMaxConcurrent = %d, want 5", cfg.HealthMaxConcurrent)
	}
	if cfg.ActivityMetadataLimit != 2048 {
		t.Fatalf("ActivityMetadataLimit = %d, want 2048", cfg.ActivityMetadataLimit)
	}
}

func TestLoadObservabilitySettingsFromEnv(t *testing.T) {
	setValidBaseEnv(t)
	t.Setenv("HEALTHCHECK_INTERVAL", " 1m ")
	t.Setenv("HEALTHCHECK_TIMEOUT", "3s")
	t.Setenv("HEALTHCHECK_MAX_CONCURRENT", "2")
	t.Setenv("ACTIVITY_METADATA_LIMIT", "1024")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HealthInterval != time.Minute {
		t.Fatalf("HealthInterval = %s, want 1m", cfg.HealthInterval)
	}
	if cfg.HealthTimeout != 3*time.Second {
		t.Fatalf("HealthTimeout = %s, want 3s", cfg.HealthTimeout)
	}
	if cfg.HealthMaxConcurrent != 2 {
		t.Fatalf("HealthMaxConcurrent = %d, want 2", cfg.HealthMaxConcurrent)
	}
	if cfg.ActivityMetadataLimit != 1024 {
		t.Fatalf("ActivityMetadataLimit = %d, want 1024", cfg.ActivityMetadataLimit)
	}
}

func TestLoadObservabilitySettingsAllowsDisabledPoller(t *testing.T) {
	setValidBaseEnv(t)
	t.Setenv("HEALTHCHECK_INTERVAL", "0")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HealthInterval != 0 {
		t.Fatalf("HealthInterval = %s, want 0 (disabled)", cfg.HealthInterval)
	}
}

func TestLoadObservabilitySettingsRejectsInvalid(t *testing.T) {
	cases := []struct {
		name  string
		key   string
		value string
	}{
		{"bad_interval", "HEALTHCHECK_INTERVAL", "soon"},
		{"negative_interval", "HEALTHCHECK_INTERVAL", "-30s"},
		{"bad_timeout", "HEALTHCHECK_TIMEOUT", "soon"},
		{"zero_timeout", "HEALTHCHECK_TIMEOUT", "0"},
		{"bad_concurrency", "HEALTHCHECK_MAX_CONCURRENT", "many"},
		{"zero_concurrency", "HEALTHCHECK_MAX_CONCURRENT", "0"},
		{"bad_metadata_limit", "ACTIVITY_METADATA_LIMIT", "big"},
		{"zero_metadata_limit", "ACTIVITY_METADATA_LIMIT", "0"},
		{"huge_metadata_limit", "ACTIVITY_METADATA_LIMIT", "1048576"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setValidBaseEnv(t)
			t.Setenv(tc.key, tc.value)
			if _, err := Load(); err == nil {
				t.Fatalf("expected error for %s=%s", tc.key, tc.value)
			}
		})
	}
}

// TestLoadTrustedProxiesDefaultsEmpty asserts the safe default: no proxy is
// trusted, so forwarded headers are ignored unless explicitly configured.
func TestLoadTrustedProxiesDefaultsEmpty(t *testing.T) {
	setValidBaseEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.TrustedProxies) != 0 {
		t.Fatalf("TrustedProxies = %v, want empty by default", cfg.TrustedProxies)
	}
}

// TestLoadTrustedProxiesFromEnv parses a comma-separated list, trimming
// whitespace and dropping empty entries while preserving order.
func TestLoadTrustedProxiesFromEnv(t *testing.T) {
	setValidBaseEnv(t)
	t.Setenv("TRUSTED_PROXIES", " 172.18.0.3 , 10.0.0.2 ,, 172.19.0.0/16 ")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{"172.18.0.3", "10.0.0.2", "172.19.0.0/16"}
	if len(cfg.TrustedProxies) != len(want) {
		t.Fatalf("TrustedProxies = %v, want %v", cfg.TrustedProxies, want)
	}
	for i := range want {
		if cfg.TrustedProxies[i] != want[i] {
			t.Fatalf("TrustedProxies[%d] = %q, want %q", i, cfg.TrustedProxies[i], want[i])
		}
	}
}

func TestLoadInstallerSettingsDefaultsDisabled(t *testing.T) {
	setValidBaseEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.InstallerBaseURL != "" {
		t.Errorf("InstallerBaseURL = %q, want empty", cfg.InstallerBaseURL)
	}
	if cfg.InstallerToken != "" {
		t.Errorf("InstallerToken should be empty by default")
	}
	if cfg.InstallerMaxUploadBytes != defaultInstallerMaxUpload {
		t.Errorf("InstallerMaxUploadBytes = %d, want %d", cfg.InstallerMaxUploadBytes, defaultInstallerMaxUpload)
	}
}

func TestLoadInstallerSettingsFromEnv(t *testing.T) {
	setValidBaseEnv(t)
	t.Setenv("INSTALLER_BASE_URL", "http://installer:8090/")
	t.Setenv("INSTALLER_TOKEN", "installer-token-value")
	t.Setenv("INSTALLER_MAX_UPLOAD_BYTES", "1048576")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.InstallerBaseURL != "http://installer:8090" {
		t.Errorf("InstallerBaseURL = %q (trailing slash must be trimmed)", cfg.InstallerBaseURL)
	}
	if cfg.InstallerToken != "installer-token-value" {
		t.Errorf("InstallerToken not loaded")
	}
	if cfg.InstallerMaxUploadBytes != 1048576 {
		t.Errorf("InstallerMaxUploadBytes = %d", cfg.InstallerMaxUploadBytes)
	}
}

func TestLoadInstallerSettingsTokenFileTakesPrecedence(t *testing.T) {
	setValidBaseEnv(t)
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "installer-token.txt")
	if err := os.WriteFile(tokenFile, []byte("  file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("INSTALLER_BASE_URL", "http://installer:8090")
	t.Setenv("INSTALLER_TOKEN", "env-token")
	t.Setenv("INSTALLER_TOKEN_FILE", tokenFile)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.InstallerToken != "file-token" {
		t.Errorf("InstallerToken = %q, want the trimmed file value", cfg.InstallerToken)
	}
}

func TestLoadInstallerSettingsRejectsInvalid(t *testing.T) {
	cases := []struct {
		name     string
		baseURL  string
		token    string
		maxBytes string
	}{
		{"bad_scheme", "ftp://installer", "tok", ""},
		{"token_without_url", "", "tok", ""},
		{"url_without_token", "http://installer:8090", "", ""},
		{"bad_max_upload", "http://installer:8090", "tok", "abc"},
		{"zero_max_upload", "http://installer:8090", "tok", "0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setValidBaseEnv(t)
			t.Setenv("INSTALLER_BASE_URL", tc.baseURL)
			t.Setenv("INSTALLER_TOKEN", tc.token)
			t.Setenv("INSTALLER_MAX_UPLOAD_BYTES", tc.maxBytes)
			if _, err := Load(); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
