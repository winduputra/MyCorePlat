package toolauth

import (
	"context"
	"crypto/hmac"
	"crypto/subtle"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// VerifyInput is everything a tool needs to verify one received request. The
// caller is responsible for having read the body first when the request is
// buffered (so BodySHA256 covers the exact received bytes) and for exposing the
// trailing headers in Trailer after the body was consumed.
type VerifyInput struct {
	Method     string
	Path       string
	Query      string
	Header     http.Header
	Trailer    http.Header
	BodySHA256 string
}

// Verifier checks the signature, clock skew, key id, body integrity and nonce
// of an inbound request. It is safe for concurrent use.
type Verifier struct {
	Keys       KeySet
	Skew       time.Duration
	NonceTTL   time.Duration
	NonceStore NonceStore
	// Now is optional; defaults to time.Now. Useful for tests.
	Now func() time.Time
}

// Verify returns nil only when the request may be processed. Every error means
// the request must be rejected (401/400) and never processed.
//
// Order of checks follows the integration contract: headers → key id → HMAC →
// timestamp window → body integrity → nonce. Nonce storage is mandatory: if it
// is not configured or cannot be consulted, verification fails closed with
// ErrNonceStoreUnavailable.
func (v *Verifier) Verify(ctx context.Context, in VerifyInput) error {
	sig := headerValue(in.Header, HeaderSignature)
	keyID := headerValue(in.Header, HeaderKeyID)
	timestampRaw := headerValue(in.Header, HeaderTimestamp)
	nonce := headerValue(in.Header, HeaderNonce)
	if sig == "" || keyID == "" || timestampRaw == "" || nonce == "" {
		return ErrMissingSignature
	}
	timestamp, err := strconv.ParseInt(timestampRaw, 10, 64)
	if err != nil {
		return ErrMissingSignature
	}

	key, ok := v.Keys.Lookup(keyID)
	if !ok {
		return ErrUnknownKey
	}
	if key.Status == KeyStatusRevoked {
		return ErrRevokedKey
	}

	now := v.now()
	if !key.Usable(now) {
		return ErrKeyExpired
	}

	streamed, err := v.verifySignature(key, in, sig, keyID, timestampRaw, nonce)
	if err != nil {
		return err
	}

	skew := v.Skew
	if skew <= 0 {
		skew = DefaultSkew
	}
	if now.Sub(time.Unix(timestamp, 0)) > skew || time.Unix(timestamp, 0).Sub(now) > skew {
		return ErrTimestampOutOfRange
	}

	if streamed {
		if err := v.verifyStreamedDigest(key, in, sig, keyID, timestampRaw, nonce); err != nil {
			return err
		}
	}

	return v.checkNonce(ctx, keyID, nonce)
}

// verifySignature reports whether the signature matches the buffered form (real
// body hash) or the streamed form (BodyHashStreamed marker).
func (v *Verifier) verifySignature(key Key, in VerifyInput, sig, keyID, timestampRaw, nonce string) (bool, error) {
	bodyHash := in.BodySHA256
	if bodyHash == "" {
		bodyHash = EmptyBodySHA256
	}
	buffered := CanonicalString(in.Method, in.Path, in.Query, keyID, timestampRaw, nonce, bodyHash)
	if hmac.Equal([]byte(sig), []byte(sign(key.Secret(), buffered))) {
		return false, nil
	}
	streamedCanonical := CanonicalString(in.Method, in.Path, in.Query, keyID, timestampRaw, nonce, BodyHashStreamed)
	if hmac.Equal([]byte(sig), []byte(sign(key.Secret(), streamedCanonical))) {
		return true, nil
	}
	return false, ErrSignatureMismatch
}

// verifyStreamedDigest proves the streamed bytes were covered by the signature.
func (v *Verifier) verifyStreamedDigest(key Key, in VerifyInput, _ string, keyID, timestampRaw, nonce string) error {
	digestValue := headerValue(in.Trailer, HeaderBodyDigest)
	digestSig := headerValue(in.Trailer, HeaderBodySignature)
	if digestValue == "" || digestSig == "" {
		return ErrStreamedDigestMissing
	}
	bodyHash := in.BodySHA256
	if bodyHash == "" {
		return ErrBodyHashMismatch
	}
	expectedDigest := "sha-256=" + bodyHash
	if subtle.ConstantTimeCompare([]byte(expectedDigest), []byte(digestValue)) != 1 {
		return ErrBodyHashMismatch
	}
	canonical := CanonicalString(in.Method, in.Path, in.Query, keyID, timestampRaw, nonce, BodyHashStreamed)
	if !hmac.Equal([]byte(digestSig), []byte(BodyDigestSignature(key.Secret(), canonical, digestValue))) {
		return ErrSignatureMismatch
	}
	return nil
}

// checkNonce enforces atomic single-use of a keyID+nonce pair and fails closed
// when replay storage is unavailable.
func (v *Verifier) checkNonce(ctx context.Context, keyID, nonce string) error {
	if v.NonceStore == nil {
		return ErrNonceStoreUnavailable
	}
	ttl := v.NonceTTL
	if ttl <= 0 {
		ttl = DefaultNonceTTL
	}
	err := v.NonceStore.CheckAndStore(ctx, keyID, nonce, ttl)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrNonceReused):
		return ErrNonceReused
	default:
		// Any other failure means we cannot rule out a replay: fail closed.
		return ErrNonceStoreUnavailable
	}
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func headerValue(h http.Header, name string) string {
	if h == nil {
		return ""
	}
	return h.Get(name)
}

// NonceStore records a keyID+nonce pair exactly once.
type NonceStore interface {
	// CheckAndStore atomically stores nonce for keyID and returns nil on the
	// first sighting, or ErrNonceReused when the pair already exists. Any other
	// error means replay protection is unavailable and the caller must fail
	// closed.
	CheckAndStore(ctx context.Context, keyID, nonce string, ttl time.Duration) error
}

// InMemoryNonceStore is a process-local store for unit tests and single-process
// local development only.
//
// It is NOT an acceptable final replay-protection mechanism: entries vanish on
// restart, are invisible to other replicas, and grow with traffic until pruned,
// so it cannot close the replay window in a real deployment. Do not claim replay
// protection is active when only this store is configured.
type InMemoryNonceStore struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

// NewInMemoryNonceStore returns an empty in-memory store.
func NewInMemoryNonceStore() *InMemoryNonceStore {
	return &InMemoryNonceStore{entries: make(map[string]time.Time)}
}

// CheckAndStore implements NonceStore atomically under a mutex.
func (s *InMemoryNonceStore) CheckAndStore(_ context.Context, keyID, nonce string, ttl time.Duration) error {
	now := time.Now()
	key := keyID + "\x00" + nonce

	s.mu.Lock()
	defer s.mu.Unlock()
	for existing, expiresAt := range s.entries {
		if !now.Before(expiresAt) {
			delete(s.entries, existing)
		}
	}
	if expiresAt, exists := s.entries[key]; exists && now.Before(expiresAt) {
		return ErrNonceReused
	}
	s.entries[key] = now.Add(ttl)
	return nil
}
