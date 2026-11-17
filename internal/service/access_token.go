package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/winduputra/MyCorePlat/internal/model"
)

// AccessTokenPrefix is the recognizable marker every access token starts with.
// It lets operators identify a leaked token in logs or tickets without the
// value being a secret, exactly like the session cookie naming convention.
const AccessTokenPrefix = "tbpbj"

// tokenPrefixLen is the number of base64url characters kept for the displayable
// prefix. 8 characters identify a token in the admin UI without revealing any
// meaningful part of the secret.
const tokenPrefixLen = 8

// tokenSecretBytes is the entropy of the secret half of a token. 32 bytes (256
// bits) is well beyond any practical brute-force budget.
const tokenSecretBytes = 32

// Access-token sentinel errors. Callers use errors.Is to distinguish them.
//
// ErrAccessTokenInvalid is deliberately generic: the gateway maps every failure
// (unknown, expired, revoked, wrong tool) to it so a caller cannot probe which
// condition failed.
var (
	ErrAccessTokenInvalid        = errors.New("access token is invalid")
	ErrAccessTokenNotFound       = errors.New("access token not found")
	ErrAccessTokenInvalidInput   = errors.New("access token input is invalid")
	ErrAccessTokenExpiryRequired = errors.New("access token requires a future expiry")
	ErrAccessTokenExpiryTooLong  = errors.New("access token expiry exceeds the maximum")
	ErrAccessTokenHashCollision  = errors.New("access token hash already exists")
)

// AccessTokenRepository is the persistence interface the token service needs.
type AccessTokenRepository interface {
	Create(ctx context.Context, token *model.AccessToken) error
	FindByHash(ctx context.Context, hash string) (*model.AccessToken, error)
	ListByTool(ctx context.Context, toolID uint64) ([]model.AccessToken, error)
	Revoke(ctx context.Context, toolID, id uint64, at time.Time) error
	TouchLastUsed(ctx context.Context, id uint64, at time.Time) error
}

// AccessTokenInput carries the admin-supplied fields for a new token. The
// plaintext is never part of the input; it is generated and returned once.
type AccessTokenInput struct {
	ToolID           uint64
	CreatedByAdminID uint64
	RecipientLabel   string
	// ExpiresAt is optional. When zero the service applies DefaultTTL.
	ExpiresAt time.Time
}

// AccessTokenOptions bounds token lifetimes. Expiry is mandatory: a zero
// DefaultTTL makes Create fail rather than mint a non-expiring token.
type AccessTokenOptions struct {
	DefaultTTL time.Duration
	MaxTTL     time.Duration
}

// AccessTokenService creates, validates, lists, and revokes per-tool tokens.
// Only hashes ever reach the repository.
type AccessTokenService struct {
	repo AccessTokenRepository
	opts AccessTokenOptions
}

// NewAccessTokenService constructs the service.
func NewAccessTokenService(repo AccessTokenRepository, opts AccessTokenOptions) *AccessTokenService {
	return &AccessTokenService{repo: repo, opts: opts}
}

// Create mints a token bound to exactly one tool. It returns the PLAINTEXT token
// for one-time display and the persisted row. The plaintext is never stored.
func (s *AccessTokenService) Create(ctx context.Context, in AccessTokenInput, now time.Time) (string, *model.AccessToken, error) {
	if in.ToolID == 0 || in.CreatedByAdminID == 0 {
		return "", nil, ErrAccessTokenInvalidInput
	}

	expiresAt, err := s.resolveExpiry(in.ExpiresAt, now)
	if err != nil {
		return "", nil, err
	}

	plaintext, prefix, err := GenerateAccessToken()
	if err != nil {
		return "", nil, err
	}

	var label *string
	if trimmed := strings.TrimSpace(in.RecipientLabel); trimmed != "" {
		label = &trimmed
	}

	token := &model.AccessToken{
		ToolID:           in.ToolID,
		TokenHash:        HashToken(plaintext),
		TokenPrefix:      prefix,
		RecipientLabel:   label,
		ExpiresAt:        expiresAt,
		CreatedByAdminID: in.CreatedByAdminID,
		CreatedAt:        now.UTC(),
	}
	if err := s.repo.Create(ctx, token); err != nil {
		return "", nil, fmt.Errorf("create access token: %w", err)
	}
	return plaintext, token, nil
}

// resolveExpiry applies the default TTL when unset and enforces both the
// mandatory-expiry rule and the configured maximum.
func (s *AccessTokenService) resolveExpiry(requested time.Time, now time.Time) (time.Time, error) {
	now = now.UTC()

	if requested.IsZero() {
		if s.opts.DefaultTTL <= 0 {
			return time.Time{}, ErrAccessTokenExpiryRequired
		}
		return now.Add(s.opts.DefaultTTL), nil
	}

	requested = requested.UTC()
	if !requested.After(now) {
		return time.Time{}, ErrAccessTokenExpiryRequired
	}
	if s.opts.MaxTTL > 0 && requested.After(now.Add(s.opts.MaxTTL)) {
		return time.Time{}, ErrAccessTokenExpiryTooLong
	}
	return requested, nil
}

// Validate checks a plaintext token against the tool that owns it. The check is
// tool-scoped so a token minted for one tool never authorizes another.
//
// Every failure returns ErrAccessTokenInvalid so the caller cannot distinguish
// "unknown token" from "wrong tool" from "expired" from "revoked".
func (s *AccessTokenService) Validate(ctx context.Context, plaintext string, toolID uint64, now time.Time) (*model.AccessToken, error) {
	prefix, ok := accessTokenPrefixOf(plaintext)
	if !ok {
		return nil, ErrAccessTokenInvalid
	}
	_ = prefix // the prefix is validated for well-formedness only; the hash decides

	token, err := s.repo.FindByHash(ctx, HashToken(plaintext))
	if err != nil {
		if errors.Is(err, ErrAccessTokenNotFound) {
			return nil, ErrAccessTokenInvalid
		}
		return nil, err
	}
	if token == nil || token.ToolID != toolID || !token.IsLive(now.UTC()) {
		return nil, ErrAccessTokenInvalid
	}
	return token, nil
}

// Revoke marks a token revoked, but only when it belongs to the given tool. A
// cross-tool revoke attempt reports not-found rather than mutating another tool.
func (s *AccessTokenService) Revoke(ctx context.Context, toolID, id uint64, now time.Time) error {
	if toolID == 0 || id == 0 {
		return ErrAccessTokenNotFound
	}
	if err := s.repo.Revoke(ctx, toolID, id, now.UTC()); err != nil {
		return err
	}
	return nil
}

// ListByTool returns every token (live or not) for a tool, so the admin UI can
// show revoked/expired state. Only prefixes and hashes exist to display.
func (s *AccessTokenService) ListByTool(ctx context.Context, toolID uint64) ([]model.AccessToken, error) {
	if toolID == 0 {
		return nil, ErrAccessTokenInvalidInput
	}
	return s.repo.ListByTool(ctx, toolID)
}

// TouchLastUsed records token usage. It is best-effort: a failure to stamp the
// timestamp must never deny a valid request.
func (s *AccessTokenService) TouchLastUsed(ctx context.Context, id uint64, now time.Time) {
	if id == 0 {
		return
	}
	_ = s.repo.TouchLastUsed(ctx, id, now.UTC())
}

// GenerateAccessToken returns a new plaintext token and its displayable prefix.
//
// Format: tbpbj_<8-char prefix>_<secret>, where the secret is 32 random bytes
// encoded with base64 without padding.
//
// The secret alphabet deliberately excludes "_": the token is split on "_" to
// recover its prefix, so a separator inside the secret would make the token
// ambiguous. base64.RawStdEncoding (A-Z a-z 0-9 + /) has no "_", and the token
// is only ever transported in the Authorization header, so "+" and "/" are safe.
func GenerateAccessToken() (token string, prefix string, err error) {
	secret := make([]byte, tokenSecretBytes)
	if _, err := rand.Read(secret); err != nil {
		return "", "", fmt.Errorf("generate access token: %w", err)
	}
	encoded := base64.RawStdEncoding.EncodeToString(secret)

	prefix = randomPrefix()

	return AccessTokenPrefix + "_" + prefix + "_" + encoded, prefix, nil
}

// randomPrefix returns tokenPrefixLen random base64url characters used only to
// help an operator recognize a token in the admin UI.
//
// The alphabet deliberately excludes the token separator "_": base64url includes
// "_" in its alphabet, and a prefix containing it would make the token ambiguous
// to split.
func randomPrefix() string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

	out := make([]byte, tokenPrefixLen)
	buf := make([]byte, tokenPrefixLen)
	if _, err := rand.Read(buf); err != nil {
		// rand.Read failing means the process is already unhealthy; return a
		// valid-shaped prefix rather than panicking. The secret half still comes
		// from a separately checked rand.Read.
		return "00000000"
	}
	for i, b := range buf {
		out[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(out)
}

// accessTokenPrefixOf validates the shape of a plaintext token and returns its
// displayable prefix. Malformed input is rejected before any storage lookup.
func accessTokenPrefixOf(plaintext string) (string, bool) {
	parts := strings.Split(plaintext, "_")
	if len(parts) != 3 {
		return "", false
	}
	if parts[0] != AccessTokenPrefix || parts[1] == "" || parts[2] == "" {
		return "", false
	}
	return parts[1], true
}
