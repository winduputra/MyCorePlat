package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/winduputra/MyCorePlat/internal/model"
)

// fakeSessionRepo is an in-memory SessionRepository for unit tests.
type fakeSessionRepo struct {
	byHash      map[string]*model.AdminSession
	createErr   error
	findErr     error
	revokeErr   error
	createCalls int
	// capturedCreate records the row passed to Create so tests can assert that
	// only a hash (never the plaintext) reaches the repository.
	capturedCreate *model.AdminSession
}

func newFakeSessionRepo() *fakeSessionRepo {
	return &fakeSessionRepo{byHash: map[string]*model.AdminSession{}}
}

func (f *fakeSessionRepo) Create(_ context.Context, s *model.AdminSession) error {
	f.createCalls++
	f.capturedCreate = s
	if f.createErr != nil {
		return f.createErr
	}
	// Mirror real repository behavior: assign the generated ID back onto the
	// caller's struct so the service can return a session with a usable ID.
	s.ID = uint64(len(f.byHash) + 1)
	stored := *s
	f.byHash[s.SessionTokenHash] = &stored
	return nil
}

func (f *fakeSessionRepo) FindByTokenHash(_ context.Context, hash string) (*model.AdminSession, error) {
	if f.findErr != nil {
		return nil, f.findErr
	}
	s, ok := f.byHash[hash]
	if !ok {
		return nil, ErrSessionNotFound
	}
	copied := *s
	return &copied, nil
}

func (f *fakeSessionRepo) Revoke(_ context.Context, id uint64) error {
	if f.revokeErr != nil {
		return f.revokeErr
	}
	for _, s := range f.byHash {
		if s.ID == id {
			now := time.Now().UTC()
			s.RevokedAt = &now
			return nil
		}
	}
	return ErrSessionNotFound
}

// TestCreateSessionStoresOnlyHash asserts that the returned plaintext token is
// never what gets persisted; only its hash is stored.
func TestCreateSessionStoresOnlyHash(t *testing.T) {
	repo := newFakeSessionRepo()
	svc := NewSessionService(repo, time.Hour)

	plaintext, session, err := svc.Create(context.Background(), 42, SessionMeta{})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if plaintext == "" {
		t.Fatal("Create returned an empty plaintext token")
	}
	if session.SessionTokenHash == plaintext {
		t.Fatal("stored session_token_hash equals the plaintext token")
	}
	if session.SessionTokenHash != HashToken(plaintext) {
		t.Fatal("stored hash is not HashToken(plaintext)")
	}
	if repo.capturedCreate == nil {
		t.Fatal("repository.Create was not called")
	}
	if repo.capturedCreate.SessionTokenHash == plaintext {
		t.Fatal("repository received the plaintext token instead of a hash")
	}
	if repo.capturedCreate.CSRFToken == "" {
		t.Fatal("session was created without a CSRF token")
	}
	if !repo.capturedCreate.ExpiresAt.After(time.Now()) {
		t.Fatal("session expiry is not in the future")
	}
}

// TestValidateSessionAcceptsValid asserts a freshly created session validates
// and yields the owning admin id.
func TestValidateSessionAcceptsValid(t *testing.T) {
	repo := newFakeSessionRepo()
	svc := NewSessionService(repo, time.Hour)

	plaintext, _, err := svc.Create(context.Background(), 7, SessionMeta{})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}

	session, err := svc.Validate(context.Background(), plaintext)
	if err != nil {
		t.Fatalf("Validate rejected a valid session: %v", err)
	}
	if session.AdminID != 7 {
		t.Fatalf("validated session admin id = %d, want 7", session.AdminID)
	}
}

// TestValidateSessionRejectsExpired asserts expiry is enforced server-side.
func TestValidateSessionRejectsExpired(t *testing.T) {
	repo := newFakeSessionRepo()
	// Negative TTL means the session is already expired at creation.
	svc := NewSessionService(repo, -time.Minute)

	plaintext, _, err := svc.Create(context.Background(), 1, SessionMeta{})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}

	if _, err := svc.Validate(context.Background(), plaintext); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Validate error = %v, want ErrSessionExpired", err)
	}
}

// TestValidateSessionRejectsRevoked asserts revoked sessions are refused.
func TestValidateSessionRejectsRevoked(t *testing.T) {
	repo := newFakeSessionRepo()
	svc := NewSessionService(repo, time.Hour)

	plaintext, session, err := svc.Create(context.Background(), 3, SessionMeta{})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if err := svc.Revoke(context.Background(), session.ID); err != nil {
		t.Fatalf("Revoke error: %v", err)
	}

	if _, err := svc.Validate(context.Background(), plaintext); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("Validate error = %v, want ErrSessionRevoked", err)
	}
}

// TestValidateSessionRejectsUnknown asserts a random/unknown token is refused
// with ErrSessionNotFound (not treated as valid).
func TestValidateSessionRejectsUnknown(t *testing.T) {
	repo := newFakeSessionRepo()
	svc := NewSessionService(repo, time.Hour)

	if _, err := svc.Validate(context.Background(), "does-not-exist"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("Validate error = %v, want ErrSessionNotFound", err)
	}
}

// TestValidateSessionRejectsEmpty ensures an empty cookie value never validates.
func TestValidateSessionRejectsEmpty(t *testing.T) {
	svc := NewSessionService(newFakeSessionRepo(), time.Hour)
	if _, err := svc.Validate(context.Background(), ""); err == nil {
		t.Fatal("Validate accepted an empty token")
	}
}

// TestHashTokenIsStableAndUnique sanity-checks the hashing helper.
func TestHashTokenIsStableAndUnique(t *testing.T) {
	if HashToken("abc") != HashToken("abc") {
		t.Fatal("HashToken is not deterministic")
	}
	if HashToken("abc") == HashToken("abd") {
		t.Fatal("HashToken collides on distinct inputs")
	}
}
