package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/winduputra/MyCorePlat/internal/model"
)

// fakeAdminRepo is an in-memory AdminRepository for auth-service unit tests.
type fakeAdminRepo struct {
	byUsername map[string]*model.Admin
	updateErr  error
}

func newFakeAdminRepo() *fakeAdminRepo {
	return &fakeAdminRepo{byUsername: map[string]*model.Admin{}}
}

func (f *fakeAdminRepo) FindByUsername(_ context.Context, username string) (*model.Admin, error) {
	a, ok := f.byUsername[username]
	if !ok {
		return nil, ErrAdminNotFound
	}
	copied := *a
	return &copied, nil
}

func (f *fakeAdminRepo) UpdateLastLogin(_ context.Context, adminID uint64) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	for _, a := range f.byUsername {
		if a.ID == adminID {
			now := time.Now().UTC()
			a.LastLoginAt = &now
		}
	}
	return nil
}

func seedAdmin(t *testing.T, repo *fakeAdminRepo, username, password string, active bool) *model.Admin {
	t.Helper()
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("hash seed password: %v", err)
	}
	a := &model.Admin{
		ID:           1,
		Username:     username,
		PasswordHash: hash,
		Role:         "superadmin",
		IsActive:     active,
	}
	repo.byUsername[username] = a
	return a
}

func newAuthService(repo *fakeAdminRepo) (*AuthService, *fakeSessionRepo) {
	sessionRepo := newFakeSessionRepo()
	sessSvc := NewSessionService(sessionRepo, time.Hour)
	return NewAuthService(repo, sessSvc), sessionRepo
}

// TestLoginSucceedsWithCorrectCredentials asserts a valid login yields a
// session and updates last_login.
func TestLoginSucceedsWithCorrectCredentials(t *testing.T) {
	repo := newFakeAdminRepo()
	seedAdmin(t, repo, "alice", "correct-horse", true)
	svc, _ := newAuthService(repo)

	plaintext, session, err := svc.Login(context.Background(), "alice", "correct-horse", SessionMeta{})
	if err != nil {
		t.Fatalf("Login failed for valid credentials: %v", err)
	}
	if plaintext == "" || session == nil {
		t.Fatal("Login returned no session")
	}
	if repo.byUsername["alice"].LastLoginAt == nil {
		t.Fatal("last_login_at was not updated on successful login")
	}
}

// TestLoginRejectsWrongPassword asserts a bad password is refused and yields no
// session.
func TestLoginRejectsWrongPassword(t *testing.T) {
	repo := newFakeAdminRepo()
	seedAdmin(t, repo, "alice", "correct-horse", true)
	svc, sessionRepo := newAuthService(repo)

	_, _, err := svc.Login(context.Background(), "alice", "wrong-password", SessionMeta{})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login error = %v, want ErrInvalidCredentials", err)
	}
	if sessionRepo.createCalls != 0 {
		t.Fatal("a session was created despite invalid credentials")
	}
}

// TestLoginRejectsUnknownUserWithSameError asserts user enumeration is not
// possible: an unknown user produces the SAME error as a wrong password.
func TestLoginRejectsUnknownUserWithSameError(t *testing.T) {
	repo := newFakeAdminRepo()
	seedAdmin(t, repo, "alice", "correct-horse", true)
	svc, _ := newAuthService(repo)

	_, _, err := svc.Login(context.Background(), "ghost", "whatever", SessionMeta{})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login error = %v, want ErrInvalidCredentials (must not reveal existence)", err)
	}
}

// TestLoginRejectsInactiveAdmin asserts disabled accounts cannot log in even
// with the right password.
func TestLoginRejectsInactiveAdmin(t *testing.T) {
	repo := newFakeAdminRepo()
	seedAdmin(t, repo, "alice", "correct-horse", false)
	svc, sessionRepo := newAuthService(repo)

	_, _, err := svc.Login(context.Background(), "alice", "correct-horse", SessionMeta{})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login error = %v, want ErrInvalidCredentials for inactive admin", err)
	}
	if sessionRepo.createCalls != 0 {
		t.Fatal("a session was created for an inactive admin")
	}
}

// TestLoginRejectsEmptyInputs asserts blank credentials are refused.
func TestLoginRejectsEmptyInputs(t *testing.T) {
	repo := newFakeAdminRepo()
	seedAdmin(t, repo, "alice", "correct-horse", true)
	svc, _ := newAuthService(repo)

	if _, _, err := svc.Login(context.Background(), "", "x", SessionMeta{}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("empty username error = %v, want ErrInvalidCredentials", err)
	}
	if _, _, err := svc.Login(context.Background(), "alice", "", SessionMeta{}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("empty password error = %v, want ErrInvalidCredentials", err)
	}
}
