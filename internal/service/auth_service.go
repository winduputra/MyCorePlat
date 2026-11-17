package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/winduputra/MyCorePlat/internal/model"
)

// ErrInvalidCredentials is returned for every failed login — unknown user,
// wrong password, and inactive account alike — so responses cannot be used to
// enumerate accounts.
var ErrInvalidCredentials = errors.New("invalid credentials")

// ErrAdminNotFound signals that no admin matches the given identity. The
// repository layer returns its own equivalent sentinel; the auth service treats
// any "not found" case as ErrInvalidCredentials.
var ErrAdminNotFound = errors.New("admin not found")

// AdminRepository is the persistence interface the auth service needs to look
// up admins and record login timestamps.
type AdminRepository interface {
	FindByUsername(ctx context.Context, username string) (*model.Admin, error)
	UpdateLastLogin(ctx context.Context, adminID uint64) error
}

// AuthService orchestrates credential verification and session issuance.
type AuthService struct {
	admins   AdminRepository
	sessions *SessionService
}

// NewAuthService constructs an AuthService.
func NewAuthService(admins AdminRepository, sessions *SessionService) *AuthService {
	return &AuthService{admins: admins, sessions: sessions}
}

// Login verifies credentials and, on success, creates a session and records the
// login time. It returns the plaintext session token for the caller to place in
// an HttpOnly cookie. All failures return ErrInvalidCredentials; passwords and
// tokens are never logged or returned in errors.
func (s *AuthService) Login(ctx context.Context, username, password string, meta SessionMeta) (string, *model.AdminSession, error) {
	if username == "" || password == "" {
		return "", nil, ErrInvalidCredentials
	}

	admin, err := s.admins.FindByUsername(ctx, username)
	if err != nil {
		// Map "not found" to the same generic error; any other repository error
		// is surfaced so operational issues remain visible.
		if errors.Is(err, ErrAdminNotFound) {
			return "", nil, ErrInvalidCredentials
		}
		return "", nil, fmt.Errorf("login lookup: %w", err)
	}

	if !admin.IsActive {
		return "", nil, ErrInvalidCredentials
	}

	if ok, err := VerifyPassword(password, admin.PasswordHash); err != nil || !ok {
		return "", nil, ErrInvalidCredentials
	}

	token, session, err := s.sessions.Create(ctx, admin.ID, meta)
	if err != nil {
		return "", nil, fmt.Errorf("login create session: %w", err)
	}

	// Best-effort: a failure to stamp last_login must not fail the login.
	_ = s.admins.UpdateLastLogin(ctx, admin.ID)

	return token, session, nil
}

// Logout revokes the given session. It is safe to call with an unknown id.
func (s *AuthService) Logout(ctx context.Context, sessionID uint64) error {
	return s.sessions.Revoke(ctx, sessionID)
}
