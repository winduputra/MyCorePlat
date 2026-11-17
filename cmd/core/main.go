// Command core is the entrypoint for the Tools BPBJ Core application:
// the browser-facing Gin gateway and admin UI.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/winduputra/MyCorePlat/internal/config"
	"github.com/winduputra/MyCorePlat/internal/gateway"
	"github.com/winduputra/MyCorePlat/internal/handlers"
	"github.com/winduputra/MyCorePlat/internal/installerclient"
	"github.com/winduputra/MyCorePlat/internal/middleware"
	"github.com/winduputra/MyCorePlat/internal/repository"
	"github.com/winduputra/MyCorePlat/internal/router"
	"github.com/winduputra/MyCorePlat/internal/service"
	"github.com/winduputra/MyCorePlat/pkg/toolauth"
)

func main() {
	// Container health probe mode: `core -healthcheck` performs one HTTP GET
	// against the local /health endpoint and exits 0 (healthy) or 1 (unhealthy).
	// This exists because the runtime image is distroless (no shell, curl or
	// wget), so the binary is the only executable available to the Docker
	// healthcheck. It reads no secrets and prints no configuration.
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		if err := healthcheck(); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if err := run(); err != nil {
		log.Fatalf("core: fatal: %v", err)
	}
}

// healthcheck probes the local server's unauthenticated /health endpoint.
func healthcheck() error {
	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	if addr[0] == ':' {
		addr = "127.0.0.1" + addr
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + addr + "/health")
	if err != nil {
		return errors.New("health endpoint unreachable")
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health endpoint returned status %d", resp.StatusCode)
	}
	return nil
}

// run wires configuration, router, and the HTTP server, then serves until an
// interrupt/terminate signal triggers a graceful shutdown.
func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// Connect to the database before serving. Fail fast: a Core instance that
	// cannot reach its database is not useful and must not serve traffic.
	db, err := repository.Open(context.Background(), cfg.DatabaseDSN, repository.DefaultPoolSettings())
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := repository.Close(db); closeErr != nil {
			log.Printf("core: closing database: %v", closeErr)
		}
	}()

	// Trusted reverse-proxy resolution. When TRUSTED_PROXIES is empty (the
	// default) the TCP peer address is used and forwarded headers are ignored,
	// so a direct client cannot forge its address. Only when the operator lists
	// the edge proxy addresses is X-Forwarded-For honoured, and only for
	// connections that actually come from those addresses.
	ipResolver, err := service.NewClientIPResolver(cfg.TrustedProxies)
	if err != nil {
		return err
	}

	// Authentication stack: repositories -> services -> handlers.
	sessionSvc := service.NewSessionService(repository.NewSessionRepository(db), cfg.SessionTTL)
	authSvc := service.NewAuthService(repository.NewAdminRepository(db), sessionSvc)
	preAuthCSRF := service.NewPreAuthCSRFService(cfg.CSRFSecret, cfg.PreAuthCSRFTTL)
	authHandler := handlers.NewAuthHandler(authSvc, preAuthCSRF, handlers.AuthOptions{
		CookieName:      middleware.SessionCookieName,
		CookieSecure:    cfg.CookieSecure,
		CookiePath:      "/",
		SessionTTL:      int(cfg.SessionTTL.Seconds()),
		PreAuthCSRFTTL:  int(cfg.PreAuthCSRFTTL.Seconds()),
		LoginRateWindow: cfg.LoginRateWindow,
	})
	authHandler.SetClientIPResolver(ipResolver)
	// Login brute-force throttling (Task 14, M-01). The limiter state is shared
	// across requests (per-IP and per-username), so it must live here rather
	// than inside a handler. Limits come from configuration, never hardcoded.
	authHandler.SetLoginLimiters(
		service.NewRateLimiter(service.RateLimiterConfig{Limit: cfg.LoginRateLimit, Window: cfg.LoginRateWindow}),
		service.NewRateLimiter(service.RateLimiterConfig{Limit: cfg.LoginRateLimit, Window: cfg.LoginRateWindow}),
	)

	// Tool registry stack: repository → service → handler.
	toolSvc := service.NewToolService(repository.NewToolRepository(db), service.NewUpstreamAllowlist(cfg.UpstreamAllowedHosts...))
	toolsHandler, err := handlers.NewAdminToolsHandler(toolSvc, handlers.AdminToolsOptions{})
	if err != nil {
		return err
	}

	// Access-token lifecycle (Task 10): repository → service → handler. Only the
	// SHA-256 hash is stored; the plaintext is returned exactly once on creation.
	tokenSvc := service.NewAccessTokenService(repository.NewAccessTokenRepository(db), service.AccessTokenOptions{
		DefaultTTL: cfg.TokenDefaultTTL,
		MaxTTL:     cfg.TokenMaxTTL,
	})
	tokensHandler, err := handlers.NewAdminTokensHandler(toolSvc, tokenSvc, handlers.AdminTokensOptions{})
	if err != nil {
		return err
	}
	// Token-validation throttling is per source IP and shared across requests, so
	// a per-request limiter would enforce nothing.
	tokenLimiter := service.NewRateLimiter(service.RateLimiterConfig{
		Limit:  cfg.TokenRateLimit,
		Window: cfg.TokenRateWindow,
	})

	// Activity audit (Task 11). Metadata is sanitized and size-bounded inside the
	// service; a failed insert never changes the caller's response.
	activitySvc := service.NewActivityService(repository.NewActivityLogRepository(db), cfg.ActivityMetadataLimit)

	// Attach auditing to every admin mutation path. The setter keeps the
	// handlers usable without a recorder (tests) and avoids constructor churn.
	authHandler.SetActivityRecorder(activitySvc)
	toolsHandler.SetActivityRecorder(activitySvc)
	tokensHandler.SetActivityRecorder(activitySvc)

	// Consistent client-address derivation across logging and throttling.
	toolsHandler.SetClientIPResolver(ipResolver)
	tokensHandler.SetClientIPResolver(ipResolver)

	// Per-tool signing keys (Task 8). In production the key directory is
	// required, so a Core without keys never forwards an unsigned request.
	var signer gateway.RequestSigner
	if cfg.ToolHMACKeysDir != "" {
		signer = toolauth.NewSigner(toolauth.NewFileKeyStore(cfg.ToolHMACKeysDir))
	}

	// Public tool gateway. Reads tool configuration from the registry and
	// proxies to the internal upstream, signing every forwarded request.
	// DNS/pinned-IP protection (Task 9) is not implemented yet.
	// Server-side upstream address policy (Task 9). Loopback, link-local,
	// multicast, unspecified, reserved and metadata addresses are always denied;
	// the CIDR list says which address ranges a resolved tool hostname may use.
	upstreamPolicy := service.DefaultUpstreamIPPolicy()
	if len(cfg.UpstreamAllowedCIDRs) > 0 {
		upstreamPolicy, err = service.NewUpstreamIPPolicy(cfg.UpstreamAllowedCIDRs)
		if err != nil {
			return err
		}
	}

	gatewayHandler := gateway.New(toolSvc, gateway.Options{
		MaxBodyBytes:          cfg.GatewayMaxBodyBytes,
		ConnectTimeout:        cfg.GatewayConnectTimeout,
		ResponseHeaderTimeout: cfg.GatewayResponseHeaderTimeout,
		IdleConnTimeout:       cfg.GatewayIdleConnTimeout,
		UpstreamAllowlist:     service.NewUpstreamAllowlist(cfg.UpstreamAllowedHosts...),
		Resolver:              service.SystemResolver(),
		IPPolicy:              upstreamPolicy,
		Signer:                signer,
		SignBufferBytes:       cfg.GatewaySignBufferBytes,
		TokenValidator:        tokenSvc,
		TokenRateLimiter:      tokenLimiter,
		ClientIPResolver:      ipResolver,
	})
	defer gatewayHandler.Close()

	// Replay protection lives in shared storage (hmac_nonces). Core owns the
	// only database connection, so it also prunes expired rows for the tool-side
	// verifiers that share the table.
	janitorCtx, stopJanitor := context.WithCancel(context.Background())
	defer stopJanitor()
	go runNonceJanitor(janitorCtx, repository.NewNonceRepository(db))

	// Health monitoring (Task 11). Only active tools are probed; the poller
	// reuses the same SSRF allowlist and pinned-IP transport policy as the
	// gateway (a twin dialer in the service package). A zero interval disables
	// polling, which is the documented dev/test opt-out.
	healthSvc := service.NewHealthChecker(
		repository.NewHealthTargetRepository(db),
		repository.NewToolHealthRepository(db),
		activitySvc,
		service.HealthCheckOptions{
			Interval:      cfg.HealthInterval,
			Timeout:       cfg.HealthTimeout,
			MaxConcurrent: cfg.HealthMaxConcurrent,
			Allowlist:     service.NewUpstreamAllowlist(cfg.UpstreamAllowedHosts...),
			IPPolicy:      upstreamPolicy,
			Resolver:      service.SystemResolver(),
		},
	)
	if cfg.HealthInterval > 0 {
		go healthSvc.Run(janitorCtx)
	}

	activityHandler, err := handlers.NewAdminActivityHandler(activitySvc)
	if err != nil {
		return err
	}
	healthHandler, err := handlers.NewAdminHealthHandler(toolSvc, repository.NewToolHealthRepository(db))
	if err != nil {
		return err
	}
	// Public homepage: the catalog of tools an anonymous visitor may actually use.
	catalogHandler, err := handlers.NewCatalogHandler(toolSvc)
	if err != nil {
		return err
	}

	// Dynamic tool installer. Core talks to the installer over its private
	// HTTP API; the Docker socket is never mounted into Core. When no installer
	// is configured the handler still renders, reporting that the service is
	// unavailable, so the page never breaks.
	var installerClient handlers.InstallerClient
	if cfg.InstallerBaseURL != "" {
		client, err := installerclient.New(cfg.InstallerBaseURL, cfg.InstallerToken, 15*time.Minute)
		if err != nil {
			return fmt.Errorf("configure tool installer client: %w", err)
		}
		installerClient = client
	}
	installerHandler, err := handlers.NewAdminInstallerHandler(installerClient, handlers.AdminInstallerOptions{
		MaxUploadBytes: cfg.InstallerMaxUploadBytes,
	})
	if err != nil {
		return err
	}
	installerHandler.SetActivityRecorder(activitySvc)

	srv := &http.Server{
		Addr: cfg.HTTPAddr,
		Handler: router.New(router.Deps{
			Auth:              authHandler,
			SessionValidator:  sessionSvc,
			SessionCookieName: middleware.SessionCookieName,
			LoginCSRFVerifier: preAuthCSRF,
			TrustedOrigin:     cfg.TrustedOrigin,
			Tools:             toolsHandler,
			Tokens:            tokensHandler,
			Activity:          activityHandler,
			Health:            healthHandler,
			Installer:         installerHandler,
			Catalog:           catalogHandler,
			Gateway:           gatewayHandler,
		}),
		ReadHeaderTimeout: time.Duration(cfg.ReadHeaderTimeoutSeconds) * time.Second,
	}

	// Serve in the background so the main goroutine can wait for signals.
	errCh := make(chan error, 1)
	go func() {
		log.Printf("core: listening on %s (env=%s)", cfg.HTTPAddr, cfg.Environment)
		if serveErr := srv.ListenAndServe(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- serveErr
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case serveErr := <-errCh:
		return serveErr
	case <-ctx.Done():
		log.Println("core: shutdown signal received, draining connections")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	log.Println("core: shutdown complete")
	return nil
}

// runNonceJanitor prunes expired replay-protection rows until ctx is cancelled.
// It is best effort: a failure only means expired rows survive until the next
// tick, never that replay protection stops working.
func runNonceJanitor(ctx context.Context, repo *repository.NonceRepository) {
	const interval = 5 * time.Minute

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			removed, err := repo.DeleteExpired(ctx, time.Now().UTC())
			if err != nil {
				log.Printf("core: nonce janitor: %v", err)
				continue
			}
			if removed > 0 {
				log.Printf("core: nonce janitor: pruned %d expired nonce(s)", removed)
			}
		}
	}
}
