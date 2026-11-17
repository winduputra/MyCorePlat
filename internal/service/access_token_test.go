package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/winduputra/MyCorePlat/internal/model"
)

// fakeTokenRepo is an in-memory AccessTokenRepository that mirrors the real
// repository's semantics (hash-only lookup, expiry/revocation aware reads).
type fakeTokenRepo struct {
	mu       sync.Mutex
	byID     map[uint64]*model.AccessToken
	byHash   map[string]*model.AccessToken
	nextID   uint64
	createFn func(*model.AccessToken) error
}

func newFakeTokenRepo() *fakeTokenRepo {
	return &fakeTokenRepo{
		byID:   map[uint64]*model.AccessToken{},
		byHash: map[string]*model.AccessToken{},
	}
}

func (r *fakeTokenRepo) Create(_ context.Context, token *model.AccessToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.createFn != nil {
		if err := r.createFn(token); err != nil {
			return err
		}
	}
	r.nextID++
	token.ID = r.nextID
	stored := *token
	r.byID[token.ID] = &stored
	r.byHash[token.TokenHash] = &stored
	return nil
}

func (r *fakeTokenRepo) FindByHash(_ context.Context, hash string) (*model.AccessToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	token, ok := r.byHash[hash]
	if !ok {
		return nil, ErrAccessTokenNotFound
	}
	copied := *token
	return &copied, nil
}

func (r *fakeTokenRepo) ListByTool(_ context.Context, toolID uint64) ([]model.AccessToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []model.AccessToken
	for _, token := range r.byID {
		if token.ToolID == toolID {
			out = append(out, *token)
		}
	}
	return out, nil
}

func (r *fakeTokenRepo) Revoke(_ context.Context, toolID, id uint64, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	token, ok := r.byID[id]
	if !ok || token.ToolID != toolID {
		return ErrAccessTokenNotFound
	}
	stamp := at.UTC()
	token.RevokedAt = &stamp
	return nil
}

func (r *fakeTokenRepo) TouchLastUsed(_ context.Context, id uint64, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if token, ok := r.byID[id]; ok {
		stamp := at.UTC()
		token.LastUsedAt = &stamp
	}
	return nil
}

func newTestTokenService(repo *fakeTokenRepo) *AccessTokenService {
	return NewAccessTokenService(repo, AccessTokenOptions{
		DefaultTTL: 24 * time.Hour,
		MaxTTL:     90 * 24 * time.Hour,
	})
}

func TestGenerateAccessTokenIsUniqueAndFormatted(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 200; i++ {
		token, prefix, err := GenerateAccessToken()
		if err != nil {
			t.Fatalf("GenerateAccessToken() error = %v", err)
		}
		if seen[token] {
			t.Fatal("GenerateAccessToken() produced a duplicate token")
		}
		seen[token] = true

		if !strings.HasPrefix(token, AccessTokenPrefix) {
			t.Fatalf("token %q does not start with %q", token, AccessTokenPrefix)
		}
		parts := strings.Split(token, "_")
		if len(parts) != 3 {
			t.Fatalf("token %q does not have 3 underscore-separated parts", token)
		}
		if parts[1] != prefix {
			t.Errorf("returned prefix %q != embedded part %q", prefix, parts[1])
		}
		if len(parts[1]) != tokenPrefixLen {
			t.Errorf("prefix length = %d, want %d", len(parts[1]), tokenPrefixLen)
		}
		// 32 random bytes base64url-encoded without padding is 43 characters.
		if len(parts[2]) < 43 {
			t.Errorf("secret part length = %d, want >= 43 (32 bytes of entropy)", len(parts[2]))
		}
	}
}

func TestGenerateAccessTokenHasSufficientEntropy(t *testing.T) {
	token, _, err := GenerateAccessToken()
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}
	secret := strings.Split(token, "_")[2]
	// 43 base64url chars is exactly 32 bytes of entropy.
	if len(secret) != 43 {
		t.Fatalf("secret part length = %d, want 43 (256 bits)", len(secret))
	}
}

func TestCreateAccessTokenStoresOnlyHash(t *testing.T) {
	repo := newFakeTokenRepo()
	svc := newTestTokenService(repo)

	plaintext, token, err := svc.Create(context.Background(), AccessTokenInput{
		ToolID:           7,
		CreatedByAdminID: 3,
		RecipientLabel:   "Dinas PU",
	}, time.Now())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if plaintext == "" {
		t.Fatal("Create() returned an empty plaintext token")
	}
	if token.TokenHash == plaintext {
		t.Error("stored token hash equals the plaintext")
	}
	if !strings.HasPrefix(plaintext, AccessTokenPrefix+"_"+token.TokenPrefix+"_") {
		t.Errorf("plaintext %q does not embed the stored prefix %q", plaintext, token.TokenPrefix)
	}
	if token.ToolID != 7 || token.CreatedByAdminID != 3 {
		t.Errorf("tool/admin binding = %d/%d, want 7/3", token.ToolID, token.CreatedByAdminID)
	}
	if token.ExpiresAt.IsZero() {
		t.Error("ExpiresAt is zero; expiry is mandatory")
	}
	if plaintext == "" || strings.Contains(token.TokenHash, plaintext) {
		t.Error("hash must not contain the plaintext")
	}
}

func TestCreateAccessTokenRequiresExpiry(t *testing.T) {
	repo := newFakeTokenRepo()
	svc := NewAccessTokenService(repo, AccessTokenOptions{DefaultTTL: 0})

	if _, _, err := svc.Create(context.Background(), AccessTokenInput{ToolID: 1, CreatedByAdminID: 1}, time.Now()); !errors.Is(err, ErrAccessTokenExpiryRequired) {
		t.Fatalf("Create() error = %v, want ErrAccessTokenExpiryRequired", err)
	}
}

func TestCreateAccessTokenRejectsExpiryBeyondMax(t *testing.T) {
	repo := newFakeTokenRepo()
	svc := newTestTokenService(repo)
	now := time.Now()

	_, _, err := svc.Create(context.Background(), AccessTokenInput{
		ToolID:           1,
		CreatedByAdminID: 1,
		ExpiresAt:        now.Add(91 * 24 * time.Hour),
	}, now)
	if !errors.Is(err, ErrAccessTokenExpiryTooLong) {
		t.Fatalf("Create() error = %v, want ErrAccessTokenExpiryTooLong", err)
	}
}

func TestCreateAccessTokenRejectsPastExpiry(t *testing.T) {
	repo := newFakeTokenRepo()
	svc := newTestTokenService(repo)
	now := time.Now()

	_, _, err := svc.Create(context.Background(), AccessTokenInput{
		ToolID:           1,
		CreatedByAdminID: 1,
		ExpiresAt:        now.Add(-time.Hour),
	}, now)
	if !errors.Is(err, ErrAccessTokenExpiryRequired) {
		t.Fatalf("Create() error = %v, want ErrAccessTokenExpiryRequired for a past expiry", err)
	}
}

func TestCreateAccessTokenRejectsMissingBindings(t *testing.T) {
	svc := newTestTokenService(newFakeTokenRepo())

	cases := map[string]AccessTokenInput{
		"no tool":  {CreatedByAdminID: 1},
		"no admin": {ToolID: 1},
	}
	for name, in := range cases {
		if _, _, err := svc.Create(context.Background(), in, time.Now()); !errors.Is(err, ErrAccessTokenInvalidInput) {
			t.Errorf("%s: Create() error = %v, want ErrAccessTokenInvalidInput", name, err)
		}
	}
}

func TestValidateAccessTokenAcceptsLiveTokenForItsTool(t *testing.T) {
	repo := newFakeTokenRepo()
	svc := newTestTokenService(repo)

	plaintext, created, err := svc.Create(context.Background(), AccessTokenInput{ToolID: 12, CreatedByAdminID: 1}, time.Now())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	got, err := svc.Validate(context.Background(), plaintext, 12, time.Now())
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("Validate() returned token %d, want %d", got.ID, created.ID)
	}
}

func TestValidateAccessTokenRejectsWrongTool(t *testing.T) {
	repo := newFakeTokenRepo()
	svc := newTestTokenService(repo)

	plaintext, _, err := svc.Create(context.Background(), AccessTokenInput{ToolID: 12, CreatedByAdminID: 1}, time.Now())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// The same generic error is returned so the caller cannot distinguish
	// "wrong tool" from "unknown token".
	if _, err := svc.Validate(context.Background(), plaintext, 13, time.Now()); !errors.Is(err, ErrAccessTokenInvalid) {
		t.Fatalf("Validate() error = %v, want ErrAccessTokenInvalid", err)
	}
}

func TestValidateAccessTokenRejectsExpired(t *testing.T) {
	repo := newFakeTokenRepo()
	svc := newTestTokenService(repo)
	now := time.Now()

	plaintext, _, err := svc.Create(context.Background(), AccessTokenInput{
		ToolID:           1,
		CreatedByAdminID: 1,
		ExpiresAt:        now.Add(time.Minute),
	}, now)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if _, err := svc.Validate(context.Background(), plaintext, 1, now.Add(2*time.Minute)); !errors.Is(err, ErrAccessTokenInvalid) {
		t.Fatalf("Validate() error = %v, want ErrAccessTokenInvalid for an expired token", err)
	}
}

func TestValidateAccessTokenRejectsRevoked(t *testing.T) {
	repo := newFakeTokenRepo()
	svc := newTestTokenService(repo)

	plaintext, created, err := svc.Create(context.Background(), AccessTokenInput{ToolID: 1, CreatedByAdminID: 1}, time.Now())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := svc.Revoke(context.Background(), 1, created.ID, time.Now()); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}

	if _, err := svc.Validate(context.Background(), plaintext, 1, time.Now()); !errors.Is(err, ErrAccessTokenInvalid) {
		t.Fatalf("Validate() error = %v, want ErrAccessTokenInvalid after revocation", err)
	}
}

func TestValidateAccessTokenRejectsUnknownAndEmpty(t *testing.T) {
	svc := newTestTokenService(newFakeTokenRepo())

	for _, token := range []string{"", "garbage", "tbpbj_abcdef_xyz"} {
		if _, err := svc.Validate(context.Background(), token, 1, time.Now()); !errors.Is(err, ErrAccessTokenInvalid) {
			t.Errorf("Validate(%q) error = %v, want ErrAccessTokenInvalid", token, err)
		}
	}
}

func TestValidateAccessTokenRejectsMalformedPrefixWithoutLookup(t *testing.T) {
	repo := &countingTokenRepo{fakeTokenRepo: newFakeTokenRepo()}
	svc := NewAccessTokenService(repo, AccessTokenOptions{DefaultTTL: time.Hour, MaxTTL: time.Hour})

	for _, token := range []string{"short", "notbpbj_x_y", AccessTokenPrefix + "zzz"} {
		if _, err := svc.Validate(context.Background(), token, 1, time.Now()); !errors.Is(err, ErrAccessTokenInvalid) {
			t.Errorf("Validate(%q) error = %v, want ErrAccessTokenInvalid", token, err)
		}
	}
	if repo.lookups != 0 {
		t.Errorf("repository lookups = %d, want 0 for malformed tokens", repo.lookups)
	}
}

func TestRevokeAccessTokenCannotTouchAnotherTool(t *testing.T) {
	repo := newFakeTokenRepo()
	svc := newTestTokenService(repo)

	plaintext, created, err := svc.Create(context.Background(), AccessTokenInput{ToolID: 1, CreatedByAdminID: 1}, time.Now())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if err := svc.Revoke(context.Background(), 2, created.ID, time.Now()); !errors.Is(err, ErrAccessTokenNotFound) {
		t.Fatalf("Revoke() with the wrong tool error = %v, want ErrAccessTokenNotFound", err)
	}
	// The token must still work for its real tool.
	if _, err := svc.Validate(context.Background(), plaintext, 1, time.Now()); err != nil {
		t.Fatalf("Validate() after a cross-tool revoke attempt error = %v", err)
	}
}

func TestListAccessTokensIsScopedToTool(t *testing.T) {
	repo := newFakeTokenRepo()
	svc := newTestTokenService(repo)

	if _, _, err := svc.Create(context.Background(), AccessTokenInput{ToolID: 1, CreatedByAdminID: 1}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Create(context.Background(), AccessTokenInput{ToolID: 2, CreatedByAdminID: 1}, time.Now()); err != nil {
		t.Fatal(err)
	}

	tokens, err := svc.ListByTool(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListByTool() error = %v", err)
	}
	if len(tokens) != 1 || tokens[0].ToolID != 1 {
		t.Fatalf("ListByTool(1) = %d tokens, want exactly 1 for tool 1", len(tokens))
	}
}

func TestValidateAccessTokenConcurrentUseIsSafe(t *testing.T) {
	repo := newFakeTokenRepo()
	svc := newTestTokenService(repo)

	plaintext, _, err := svc.Create(context.Background(), AccessTokenInput{ToolID: 5, CreatedByAdminID: 1}, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := svc.Validate(context.Background(), plaintext, 5, time.Now()); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("concurrent Validate() error = %v", err)
	}
}

// countingTokenRepo counts hash lookups so tests can prove malformed input never
// reaches storage.
type countingTokenRepo struct {
	*fakeTokenRepo
	lookups int
}

func (r *countingTokenRepo) FindByHash(ctx context.Context, hash string) (*model.AccessToken, error) {
	r.lookups++
	return r.fakeTokenRepo.FindByHash(ctx, hash)
}
