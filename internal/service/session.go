package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/winduputra/MyCorePlat/internal/model"
)

// Session-related sentinel errors. Callers use errors.Is to distinguish them
// without depending on string matching.
var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
	ErrSessionRevoked  = errors.New("session revoked")
)

// SessionRepository is the persistence interface the session service needs.
// Keeping it narrow makes the service unit-testable without a database and
// documents exactly which operations authentication requires.
type SessionRepository interface {
	Create(ctx context.Context, session *model.AdminSession) error
	FindByTokenHash(ctx context.Context, tokenHash string) (*model.AdminSession, error)
	Revoke(ctx context.Context, id uint64) error
}

// SessionMeta carries optional request context stored with the session.
type SessionMeta struct {
	IPAddress string
	UserAgent string
}

// SessionService creates, validates, and revokes admin sessions. Only hashes of
// session tokens are persisted; plaintext tokens live solely in the client's
// HttpOnly cookie.
type SessionService struct {
	repo SessionRepository
	ttl  time.Duration
}

// NewSessionService constructs a SessionService with the given absolute TTL.
func NewSessionService(repo SessionRepository, ttl time.Duration) *SessionService {
	return &SessionService{repo: repo, ttl: ttl}
}

// Create mints a new session for adminID. It returns the PLAINTEXT token (to be
// placed in the cookie by the caller) and the persisted session row. The
// plaintext is never stored; only its hash and a fresh CSRF token are.
func (s *SessionService) Create(ctx context.Context, adminID uint64, meta SessionMeta) (string, *model.AdminSession, error) {
	plaintext, err := GenerateToken()
	if err != nil {
		return "", nil, err
	}
	csrf, err := GenerateToken()
	if err != nil {
		return "", nil, err
	}

	now := time.Now().UTC()
	session := &model.AdminSession{
		AdminID:          adminID,
		SessionTokenHash: HashToken(plaintext),
		CSRFToken:        csrf,
		ExpiresAt:        now.Add(s.ttl),
		CreatedAt:        now,
	}
	if meta.IPAddress != "" {
		ip := meta.IPAddress
		session.IPAddress = &ip
	}
	if meta.UserAgent != "" {
		ua := meta.UserAgent
		session.UserAgent = &ua
	}

	if err := s.repo.Create(ctx, session); err != nil {
		return "", nil, fmt.Errorf("create session: %w", err)
	}
	return plaintext, session, nil
}

// Validate looks up the session for a plaintext token and enforces that it is
// neither expired nor revoked. It returns the live session on success.
func (s *SessionService) Validate(ctx context.Context, plaintextToken string) (*model.AdminSession, error) {
	if plaintextToken == "" {
		return nil, ErrSessionNotFound
	}

	session, err := s.repo.FindByTokenHash(ctx, HashToken(plaintextToken))
	if err != nil {
		return nil, err
	}

	if session.RevokedAt != nil {
		return nil, ErrSessionRevoked
	}
	if !session.ExpiresAt.After(time.Now().UTC()) {
		return nil, ErrSessionExpired
	}
	return session, nil
}

// Revoke marks a session as revoked (logout). It is idempotent from the
// caller's perspective: revoking an already-revoked session succeeds.
func (s *SessionService) Revoke(ctx context.Context, sessionID uint64) error {
	if sessionID == 0 {
		return ErrSessionNotFound
	}
	if err := s.repo.Revoke(ctx, sessionID); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

// GenerateToken returns a cryptographically random, URL-safe token.
func GenerateToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// HashToken returns the hex-encoded SHA-256 of a token. Session tokens are
// high-entropy random values, so a fast hash is sufficient (unlike passwords,
// which need a slow KDF) and keeps lookups cheap and indexable.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
