package repository_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/winduputra/MyCorePlat/internal/repository"
	"github.com/winduputra/MyCorePlat/pkg/toolauth"
)

func uniqueNonce(t *testing.T) string {
	t.Helper()
	token, err := toolauth.NewNonce()
	if err != nil {
		t.Fatalf("generate nonce: %v", err)
	}
	return token
}

func TestNonceRepositoryStoresOnce(t *testing.T) {
	db := openDevDB(t)
	repo := repository.NewNonceRepository(db)
	ctx := context.Background()

	keyID := "test-key-" + time.Now().UTC().Format("150405.000000")
	nonce := uniqueNonce(t)
	t.Cleanup(func() {
		_, _ = repo.DeleteExpired(ctx, time.Now().UTC().Add(24*time.Hour))
	})

	if err := repo.CheckAndStore(ctx, keyID, nonce, time.Minute); err != nil {
		t.Fatalf("first CheckAndStore error = %v, want nil", err)
	}
	if err := repo.CheckAndStore(ctx, keyID, nonce, time.Minute); !errors.Is(err, toolauth.ErrNonceReused) {
		t.Fatalf("replayed CheckAndStore error = %v, want ErrNonceReused", err)
	}

	// A different nonce for the same key is fine.
	if err := repo.CheckAndStore(ctx, keyID, uniqueNonce(t), time.Minute); err != nil {
		t.Fatalf("second distinct nonce error = %v, want nil", err)
	}
}

func TestNonceRepositoryConcurrentAdmitsExactlyOne(t *testing.T) {
	db := openDevDB(t)
	repo := repository.NewNonceRepository(db)
	ctx := context.Background()

	keyID := "test-key-concurrent-" + time.Now().UTC().Format("150405.000000")
	nonce := uniqueNonce(t)
	t.Cleanup(func() {
		_, _ = repo.DeleteExpired(ctx, time.Now().UTC().Add(24*time.Hour))
	})

	const attempts = 24
	var wg sync.WaitGroup
	results := make([]error, attempts)
	start := make(chan struct{})
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			results[idx] = repo.CheckAndStore(ctx, keyID, nonce, time.Minute)
		}(i)
	}
	close(start)
	wg.Wait()

	accepted, reused := 0, 0
	for _, err := range results {
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, toolauth.ErrNonceReused):
			reused++
		default:
			t.Fatalf("unexpected CheckAndStore error: %v", err)
		}
	}
	if accepted != 1 || reused != attempts-1 {
		t.Fatalf("accepted=%d reused=%d, want accepted=1 reused=%d", accepted, reused, attempts-1)
	}
}

func TestNonceRepositoryAllowsReuseAfterExpiry(t *testing.T) {
	db := openDevDB(t)
	repo := repository.NewNonceRepository(db)
	ctx := context.Background()

	keyID := "test-key-expiry-" + time.Now().UTC().Format("150405.000000")
	nonce := uniqueNonce(t)
	t.Cleanup(func() {
		_, _ = repo.DeleteExpired(ctx, time.Now().UTC().Add(24*time.Hour))
	})

	// Store with a TTL that is already in the past: the row exists but is stale,
	// so a later attempt must be admitted again rather than treated as replay.
	if err := repo.CheckAndStore(ctx, keyID, nonce, time.Nanosecond); err != nil {
		t.Fatalf("initial CheckAndStore error = %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	if err := repo.CheckAndStore(ctx, keyID, nonce, time.Minute); err != nil {
		t.Fatalf("CheckAndStore after expiry error = %v, want nil", err)
	}

	deleted, err := repo.DeleteExpired(ctx, time.Now().UTC().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("DeleteExpired error = %v", err)
	}
	if deleted == 0 {
		t.Fatal("DeleteExpired removed 0 rows, want at least 1")
	}
}

func TestNonceRepositoryNilHandleFailsClosed(t *testing.T) {
	repo := repository.NewNonceRepository(nil)
	if err := repo.CheckAndStore(context.Background(), "k", "n", time.Minute); !errors.Is(err, toolauth.ErrNonceStoreUnavailable) {
		t.Fatalf("nil handle error = %v, want ErrNonceStoreUnavailable", err)
	}
}
