package toolauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	activeKeyID   = "k-active"
	previousKeyID = "k-previous"
	revokedKeyID  = "k-revoked"
)

var testClock = time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)

func testSecret(fill byte) []byte {
	buf := make([]byte, 32)
	for i := range buf {
		buf[i] = fill
	}
	return buf
}

func mustKey(t *testing.T, id string, fill byte, status KeyStatus, notAfter *time.Time) Key {
	t.Helper()
	key, err := NewKey(id, testSecret(fill), status, notAfter)
	if err != nil {
		t.Fatalf("NewKey(%q) error: %v", id, err)
	}
	return key
}

func testKeySet(t *testing.T) KeySet {
	t.Helper()
	expired := testClock.Add(-time.Minute)
	set, err := NewKeySet(
		mustKey(t, activeKeyID, 1, KeyStatusActive, nil),
		mustKey(t, previousKeyID, 2, KeyStatusPrevious, nil),
		mustKey(t, revokedKeyID, 3, KeyStatusRevoked, nil),
		mustKey(t, "k-expired", 4, KeyStatusPrevious, &expired),
	)
	if err != nil {
		t.Fatalf("NewKeySet error: %v", err)
	}
	return set
}

type stubStore struct {
	sets map[string]KeySet
	err  error
}

func (s stubStore) Keys(_ context.Context, slug string) (KeySet, error) {
	if s.err != nil {
		return KeySet{}, s.err
	}
	set, ok := s.sets[slug]
	if !ok {
		return KeySet{}, ErrKeyNotFound
	}
	return set, nil
}

func newVerifier(t *testing.T) *Verifier {
	t.Helper()
	return &Verifier{
		Keys:       testKeySet(t),
		Skew:       DefaultSkew,
		NonceStore: NewInMemoryNonceStore(),
		Now:        func() time.Time { return testClock },
	}
}

// signedInput builds a correctly signed (buffered) request input.
func signedInput(t *testing.T, key Key, method, path, query, body string) VerifyInput {
	t.Helper()
	bodyHash := BodyHash([]byte(body))
	timestamp := strconv.FormatInt(testClock.Unix(), 10)
	nonce, err := generateNonce()
	if err != nil {
		t.Fatalf("generateNonce error: %v", err)
	}
	canonical := CanonicalString(method, path, query, key.ID, timestamp, nonce, bodyHash)
	header := http.Header{}
	Signature{
		KeyID:     key.ID,
		Timestamp: timestamp,
		Nonce:     nonce,
		Value:     sign(key.Secret(), canonical),
		Canonical: canonical,
	}.Apply(header)
	return VerifyInput{Method: method, Path: path, Query: query, Header: header, BodySHA256: bodyHash}
}

func TestCanonicalStringIsDeterministic(t *testing.T) {
	got := CanonicalString("POST", "/t/tool/x", "a=1", "kid", "1700000000", "nonce", "hash")
	want := "POST\n/t/tool/x\na=1\nkid\n1700000000\nnonce\nhash"
	if got != want {
		t.Fatalf("CanonicalString = %q, want %q", got, want)
	}
}

func TestVerifyAcceptsValidSignature(t *testing.T) {
	v := newVerifier(t)
	key, _ := v.Keys.Lookup(activeKeyID)

	if err := v.Verify(context.Background(), signedInput(t, key, "GET", "/t/tool/a", "x=1", "hello")); err != nil {
		t.Fatalf("Verify valid signature error = %v, want nil", err)
	}
}

func TestVerifyRejectsMissingSignatureHeaders(t *testing.T) {
	v := newVerifier(t)
	key, _ := v.Keys.Lookup(activeKeyID)

	in := signedInput(t, key, "GET", "/t/tool/a", "", "")
	for _, header := range []string{HeaderSignature, HeaderKeyID, HeaderTimestamp, HeaderNonce} {
		stripped := signedInput(t, key, "GET", "/t/tool/b", "", "")
		stripped.Header.Del(header)
		if err := v.Verify(context.Background(), stripped); !errors.Is(err, ErrMissingSignature) {
			t.Errorf("Verify without %s error = %v, want ErrMissingSignature", header, err)
		}
	}
	_ = in
}

func TestVerifyRejectsModifiedRequest(t *testing.T) {
	v := newVerifier(t)
	key, _ := v.Keys.Lookup(activeKeyID)

	cases := []struct {
		name   string
		mutate func(*VerifyInput)
	}{
		{"path", func(in *VerifyInput) { in.Path = "/t/tool/other" }},
		{"method", func(in *VerifyInput) { in.Method = "DELETE" }},
		{"query", func(in *VerifyInput) { in.Query = "x=2" }},
		{"body", func(in *VerifyInput) { in.BodySHA256 = BodyHash([]byte("tampered")) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := signedInput(t, key, "POST", "/t/tool/a", "x=1", "hello")
			tc.mutate(&in)
			if err := v.Verify(context.Background(), in); err == nil {
				t.Fatalf("Verify modified %s error = nil, want rejection", tc.name)
			}
		})
	}
}

func TestVerifyRejectsWrongSignature(t *testing.T) {
	v := newVerifier(t)
	key, _ := v.Keys.Lookup(activeKeyID)

	in := signedInput(t, key, "GET", "/t/tool/a", "", "")
	in.Header.Set(HeaderSignature, strings.Repeat("ab", 32))
	if err := v.Verify(context.Background(), in); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("Verify wrong signature error = %v, want ErrSignatureMismatch", err)
	}
}

func TestVerifyRejectsExpiredTimestamp(t *testing.T) {
	v := newVerifier(t)
	key, _ := v.Keys.Lookup(activeKeyID)

	in := signedInput(t, key, "GET", "/t/tool/a", "", "")
	old := strconv.FormatInt(testClock.Add(-2*DefaultSkew).Unix(), 10)
	in.Header.Set(HeaderTimestamp, old)
	canonical := CanonicalString(in.Method, in.Path, in.Query, key.ID, old, in.Header.Get(HeaderNonce), in.BodySHA256)
	in.Header.Set(HeaderSignature, sign(key.Secret(), canonical))

	if err := v.Verify(context.Background(), in); !errors.Is(err, ErrTimestampOutOfRange) {
		t.Fatalf("Verify expired timestamp error = %v, want ErrTimestampOutOfRange", err)
	}
}

func TestVerifyRejectsFutureTimestamp(t *testing.T) {
	v := newVerifier(t)
	key, _ := v.Keys.Lookup(activeKeyID)

	in := signedInput(t, key, "GET", "/t/tool/a", "", "")
	future := strconv.FormatInt(testClock.Add(2*DefaultSkew).Unix(), 10)
	in.Header.Set(HeaderTimestamp, future)
	canonical := CanonicalString(in.Method, in.Path, in.Query, key.ID, future, in.Header.Get(HeaderNonce), in.BodySHA256)
	in.Header.Set(HeaderSignature, sign(key.Secret(), canonical))

	if err := v.Verify(context.Background(), in); !errors.Is(err, ErrTimestampOutOfRange) {
		t.Fatalf("Verify future timestamp error = %v, want ErrTimestampOutOfRange", err)
	}
}

func TestVerifyRejectsUnknownKeyID(t *testing.T) {
	v := newVerifier(t)
	unknown := mustKey(t, "k-not-provisioned", 9, KeyStatusActive, nil)

	in := signedInput(t, unknown, "GET", "/t/tool/a", "", "")
	if err := v.Verify(context.Background(), in); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("Verify unknown key error = %v, want ErrUnknownKey", err)
	}
}

func TestVerifyRejectsRevokedKey(t *testing.T) {
	v := newVerifier(t)
	revoked, _ := v.Keys.Lookup(revokedKeyID)

	in := signedInput(t, revoked, "GET", "/t/tool/a", "", "")
	if err := v.Verify(context.Background(), in); !errors.Is(err, ErrRevokedKey) {
		t.Fatalf("Verify revoked key error = %v, want ErrRevokedKey", err)
	}
}

func TestVerifyAcceptsPreviousKeyDuringRotation(t *testing.T) {
	v := newVerifier(t)
	previous, ok := v.Keys.Lookup(previousKeyID)
	if !ok {
		t.Fatal("previous key missing from set")
	}

	// A request signed with the retired-but-still-valid key must verify while
	// the transition window is open, so rotation causes no downtime.
	if err := v.Verify(context.Background(), signedInput(t, previous, "GET", "/t/tool/a", "", "")); err != nil {
		t.Fatalf("Verify previous key error = %v, want nil", err)
	}
}

func TestVerifyRejectsExpiredPreviousKey(t *testing.T) {
	v := newVerifier(t)
	expired, ok := v.Keys.Lookup("k-expired")
	if !ok {
		t.Fatal("expired key missing from set")
	}

	in := signedInput(t, expired, "GET", "/t/tool/a", "", "")
	if err := v.Verify(context.Background(), in); !errors.Is(err, ErrKeyExpired) {
		t.Fatalf("Verify expired previous key error = %v, want ErrKeyExpired", err)
	}
}

func TestVerifyRejectsDuplicateNonce(t *testing.T) {
	v := newVerifier(t)
	key, _ := v.Keys.Lookup(activeKeyID)

	in := signedInput(t, key, "GET", "/t/tool/a", "", "")
	if err := v.Verify(context.Background(), in); err != nil {
		t.Fatalf("first Verify error = %v, want nil", err)
	}
	if err := v.Verify(context.Background(), in); !errors.Is(err, ErrNonceReused) {
		t.Fatalf("replayed Verify error = %v, want ErrNonceReused", err)
	}
}

func TestVerifyConcurrentNonceAdmittedOnce(t *testing.T) {
	v := newVerifier(t)
	key, _ := v.Keys.Lookup(activeKeyID)

	in := signedInput(t, key, "POST", "/t/tool/a", "", "body")

	const attempts = 40
	var wg sync.WaitGroup
	results := make([]error, attempts)
	start := make(chan struct{})
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			results[idx] = v.Verify(context.Background(), in)
		}(i)
	}
	close(start)
	wg.Wait()

	accepted, reused := 0, 0
	for _, err := range results {
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, ErrNonceReused):
			reused++
		default:
			t.Fatalf("unexpected error from concurrent Verify: %v", err)
		}
	}
	if accepted != 1 || reused != attempts-1 {
		t.Fatalf("concurrent Verify accepted=%d reused=%d, want accepted=1 reused=%d", accepted, reused, attempts-1)
	}
}

func TestVerifyFailsClosedWithoutNonceStore(t *testing.T) {
	v := newVerifier(t)
	v.NonceStore = nil
	key, _ := v.Keys.Lookup(activeKeyID)

	in := signedInput(t, key, "GET", "/t/tool/a", "", "")
	if err := v.Verify(context.Background(), in); !errors.Is(err, ErrNonceStoreUnavailable) {
		t.Fatalf("Verify without nonce store error = %v, want ErrNonceStoreUnavailable", err)
	}
}

type failingNonceStore struct{ err error }

func (f failingNonceStore) CheckAndStore(context.Context, string, string, time.Duration) error {
	return f.err
}

func TestVerifyFailsClosedWhenNonceStoreUnavailable(t *testing.T) {
	v := newVerifier(t)
	v.NonceStore = failingNonceStore{err: errors.New("storage down")}
	key, _ := v.Keys.Lookup(activeKeyID)

	in := signedInput(t, key, "GET", "/t/tool/a", "", "")
	if err := v.Verify(context.Background(), in); !errors.Is(err, ErrNonceStoreUnavailable) {
		t.Fatalf("Verify with failing store error = %v, want ErrNonceStoreUnavailable", err)
	}
}

// signedStreamedInput builds a streamed request (header signature over the
// BodyHashStreamed marker plus the signed digest trailer).
func signedStreamedInput(t *testing.T, key Key, body []byte) VerifyInput {
	t.Helper()
	timestamp := strconv.FormatInt(testClock.Unix(), 10)
	nonce, err := generateNonce()
	if err != nil {
		t.Fatalf("generateNonce error: %v", err)
	}
	canonical := CanonicalString("POST", "/t/tool/upload", "", key.ID, timestamp, nonce, BodyHashStreamed)
	header := http.Header{}
	Signature{KeyID: key.ID, Timestamp: timestamp, Nonce: nonce, Value: sign(key.Secret(), canonical), Canonical: canonical}.Apply(header)

	digest := StreamedDigest(body)
	trailer := http.Header{}
	trailer.Set(HeaderBodyDigest, digest)
	trailer.Set(HeaderBodySignature, BodyDigestSignature(key.Secret(), canonical, digest))

	return VerifyInput{
		Method:     "POST",
		Path:       "/t/tool/upload",
		Header:     header,
		Trailer:    trailer,
		BodySHA256: BodyHash(body),
	}
}

func TestVerifyAcceptsStreamedBodyWithSignedDigest(t *testing.T) {
	v := newVerifier(t)
	key, _ := v.Keys.Lookup(activeKeyID)

	if err := v.Verify(context.Background(), signedStreamedInput(t, key, []byte("stream-body"))); err != nil {
		t.Fatalf("Verify streamed body error = %v, want nil", err)
	}
}

func TestVerifyRejectsStreamedBodyWithoutTrailer(t *testing.T) {
	v := newVerifier(t)
	key, _ := v.Keys.Lookup(activeKeyID)

	in := signedStreamedInput(t, key, []byte("stream-body"))
	in.Trailer = nil
	if err := v.Verify(context.Background(), in); !errors.Is(err, ErrStreamedDigestMissing) {
		t.Fatalf("Verify streamed without trailer error = %v, want ErrStreamedDigestMissing", err)
	}
}

func TestVerifyRejectsTamperedStreamedBody(t *testing.T) {
	v := newVerifier(t)
	key, _ := v.Keys.Lookup(activeKeyID)

	in := signedStreamedInput(t, key, []byte("stream-body"))
	// The receiver got different bytes than the signed digest describes.
	in.BodySHA256 = BodyHash([]byte("different-body"))
	if err := v.Verify(context.Background(), in); !errors.Is(err, ErrBodyHashMismatch) {
		t.Fatalf("Verify tampered streamed body error = %v, want ErrBodyHashMismatch", err)
	}
}

func TestVerifyRejectsTamperedStreamedDigestSignature(t *testing.T) {
	v := newVerifier(t)
	key, _ := v.Keys.Lookup(activeKeyID)

	in := signedStreamedInput(t, key, []byte("stream-body"))
	in.Trailer.Set(HeaderBodySignature, strings.Repeat("cd", 32))
	if err := v.Verify(context.Background(), in); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("Verify tampered digest signature error = %v, want ErrSignatureMismatch", err)
	}
}

func TestSignerUsesActiveKeyAndAppliesHeaders(t *testing.T) {
	store := stubStore{sets: map[string]KeySet{"tool-a": testKeySet(t)}}
	signer := NewSigner(store)
	signer.now = func() time.Time { return testClock }

	sig, err := signer.Sign(context.Background(), "tool-a", "POST", "/t/tool-a/x", "a=1", BodyHash([]byte("body")))
	if err != nil {
		t.Fatalf("Sign error = %v", err)
	}
	if sig.KeyID != activeKeyID {
		t.Errorf("signed with key %q, want %q", sig.KeyID, activeKeyID)
	}
	if sig.Timestamp != strconv.FormatInt(testClock.Unix(), 10) {
		t.Errorf("timestamp = %q, want %d", sig.Timestamp, testClock.Unix())
	}
	if len(sig.Nonce) < 20 {
		t.Errorf("nonce %q looks too short", sig.Nonce)
	}

	header := http.Header{}
	sig.Apply(header)
	for _, name := range []string{HeaderSignature, HeaderKeyID, HeaderTimestamp, HeaderNonce, HeaderGateway} {
		if header.Get(name) == "" {
			t.Errorf("header %s not set", name)
		}
	}
	if header.Get(HeaderGateway) != GatewayIdentifier {
		t.Errorf("X-Gateway = %q, want %q", header.Get(HeaderGateway), GatewayIdentifier)
	}

	// The signed output must verify end to end with the matching key set.
	v := newVerifier(t)
	if err := v.Verify(context.Background(), VerifyInput{
		Method:     "POST",
		Path:       "/t/tool-a/x",
		Query:      "a=1",
		Header:     header,
		BodySHA256: BodyHash([]byte("body")),
	}); err != nil {
		t.Fatalf("Verify of signer output error = %v", err)
	}
}

func TestSignerFailsWithoutActiveKey(t *testing.T) {
	previousOnly, err := NewKeySet(mustKey(t, previousKeyID, 2, KeyStatusPrevious, nil))
	if err != nil {
		t.Fatalf("NewKeySet error: %v", err)
	}
	signer := NewSigner(stubStore{sets: map[string]KeySet{"tool-a": previousOnly}})

	if _, err := signer.Sign(context.Background(), "tool-a", "GET", "/t/tool-a", "", ""); !errors.Is(err, ErrNoActiveKey) {
		t.Fatalf("Sign without active key error = %v, want ErrNoActiveKey", err)
	}
}

func TestSignerPropagatesKeyStoreErrors(t *testing.T) {
	signer := NewSigner(stubStore{err: ErrKeyStoreUnavailable})
	if _, err := signer.Sign(context.Background(), "tool-a", "GET", "/t/tool-a", "", ""); !errors.Is(err, ErrKeyStoreUnavailable) {
		t.Fatalf("Sign error = %v, want ErrKeyStoreUnavailable", err)
	}
	if _, err := NewSigner(nil).Sign(context.Background(), "tool-a", "GET", "/t/tool-a", "", ""); !errors.Is(err, ErrKeyStoreUnavailable) {
		t.Fatalf("Sign with nil store error = %v, want ErrKeyStoreUnavailable", err)
	}
}

func TestSignerDigestTrailerBindsSameKey(t *testing.T) {
	store := stubStore{sets: map[string]KeySet{"tool-a": testKeySet(t)}}
	signer := NewSigner(store)
	signer.now = func() time.Time { return testClock }

	sig, err := signer.Sign(context.Background(), "tool-a", "POST", "/t/tool-a/upload", "", BodyHashStreamed)
	if err != nil {
		t.Fatalf("Sign error = %v", err)
	}
	body := []byte("streamed-payload")
	digest := StreamedDigest(body)
	trailerSig, err := signer.SignDigestTrailer(context.Background(), "tool-a", sig, digest)
	if err != nil {
		t.Fatalf("SignDigestTrailer error = %v", err)
	}

	v := newVerifier(t)
	if err := v.Verify(context.Background(), VerifyInput{
		Method:     "POST",
		Path:       "/t/tool-a/upload",
		Header:     http.Header{}, // filled below
		BodySHA256: BodyHash(body),
	}); err == nil {
		t.Fatal("Verify without header should fail")
	}

	header := http.Header{}
	sig.Apply(header)
	trailers := http.Header{}
	trailers.Set(HeaderBodyDigest, digest)
	trailers.Set(HeaderBodySignature, trailerSig)
	if err := v.Verify(context.Background(), VerifyInput{
		Method:     "POST",
		Path:       "/t/tool-a/upload",
		Header:     header,
		Trailer:    trailers,
		BodySHA256: BodyHash(body),
	}); err != nil {
		t.Fatalf("Verify streamed signer output error = %v", err)
	}
}

func TestKeyStringAndErrorsDoNotLeakSecret(t *testing.T) {
	key := mustKey(t, activeKeyID, 7, KeyStatusActive, nil)
	secretB64 := base64.StdEncoding.EncodeToString(key.Secret())
	secretHex := sign(key.Secret(), "probe")

	if strings.Contains(key.String(), secretB64) || strings.Contains(key.String(), secretHex) {
		t.Fatalf("Key.String leaks secret: %s", key.String())
	}

	v := newVerifier(t)
	unknown := mustKey(t, "k-other", 8, KeyStatusActive, nil)
	in := signedInput(t, unknown, "GET", "/t/tool/a", "", "")
	err := v.Verify(context.Background(), in)
	if err == nil {
		t.Fatal("Verify should fail")
	}
	msg := err.Error()
	for _, secretLike := range []string{secretB64, base64.StdEncoding.EncodeToString(unknown.Secret()), secretHex} {
		if strings.Contains(msg, secretLike) {
			t.Fatalf("error message leaks secret material: %q", msg)
		}
	}
}

func writeKeyFile(t *testing.T, dir, slug string, keys []keyFileEntry) {
	t.Helper()
	payload := keyFileFormat{ToolSlug: slug, Keys: keys}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal key file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, slug+".json"), raw, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
}

func b64(secret []byte) string { return base64.StdEncoding.EncodeToString(secret) }

func TestFileKeyStoreLoadsAndReloadsOnRotation(t *testing.T) {
	dir := t.TempDir()
	slug := "image-compressor"
	oldSecret := testSecret(1)
	newSecret := testSecret(2)
	writeKeyFile(t, dir, slug, []keyFileEntry{{KeyID: "k1", Secret: b64(oldSecret), Status: KeyStatusActive}})

	store := NewFileKeyStore(dir)
	set, err := store.Keys(context.Background(), slug)
	if err != nil {
		t.Fatalf("Keys error = %v", err)
	}
	key, ok := set.Lookup("k1")
	if !ok {
		t.Fatal("k1 not found")
	}
	if !bytes.Equal(key.Secret(), oldSecret) {
		t.Fatal("loaded secret does not match provisioned secret")
	}

	// Rotation: new key becomes active, old one stays valid as previous.
	transition := testClock.Add(10 * time.Minute)
	writeKeyFile(t, dir, slug, []keyFileEntry{
		{KeyID: "k2", Secret: b64(newSecret), Status: KeyStatusActive},
		{KeyID: "k1", Secret: b64(oldSecret), Status: KeyStatusPrevious, NotAfter: &transition},
	})
	// Ensure the modification is observable even on coarse filesystems.
	past := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(filepath.Join(dir, slug+".json"), past, past)

	rotated, err := store.Keys(context.Background(), slug)
	if err != nil {
		t.Fatalf("Keys after rotation error = %v", err)
	}
	active, err := rotated.Active(testClock)
	if err != nil {
		t.Fatalf("Active after rotation error = %v", err)
	}
	if active.ID != "k2" {
		t.Fatalf("active key = %q, want k2", active.ID)
	}
	if _, ok := rotated.Lookup("k1"); !ok {
		t.Fatal("previous key k1 must remain available during transition")
	}

	// Revocation: the retired key must be rejected even though it is present.
	revoke := testClock.Add(-time.Second)
	writeKeyFile(t, dir, slug, []keyFileEntry{
		{KeyID: "k2", Secret: b64(newSecret), Status: KeyStatusActive},
		{KeyID: "k1", Secret: b64(oldSecret), Status: KeyStatusRevoked, NotAfter: &revoke},
	})
	_ = os.Chtimes(filepath.Join(dir, slug+".json"), past.Add(-time.Second), past.Add(-time.Second))

	revokedSet, err := store.Keys(context.Background(), slug)
	if err != nil {
		t.Fatalf("Keys after revocation error = %v", err)
	}
	revokedKey, ok := revokedSet.Lookup("k1")
	if !ok {
		t.Fatal("k1 missing")
	}
	if revokedKey.Usable(testClock) {
		t.Fatal("revoked key must not be usable")
	}
}

func TestFileKeyStoreRejectsMissingFileAndBadSlug(t *testing.T) {
	store := NewFileKeyStore(t.TempDir())

	if _, err := store.Keys(context.Background(), "absent-tool"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("missing file error = %v, want ErrKeyNotFound", err)
	}
	for _, slug := range []string{"../../etc/passwd", "UPPER", "has_underscore", "trailing-", ""} {
		if _, err := store.Keys(context.Background(), slug); err == nil {
			t.Errorf("slug %q should be rejected", slug)
		}
	}
	if _, err := NewFileKeyStore("").Keys(context.Background(), "tool-a"); !errors.Is(err, ErrKeyStoreUnavailable) {
		t.Fatalf("empty dir error = %v, want ErrKeyStoreUnavailable", err)
	}
}

func TestFileKeyStoreRejectsInvalidContent(t *testing.T) {
	dir := t.TempDir()
	slug := "tool-a"

	cases := map[string][]keyFileEntry{
		"bad_base64":    {{KeyID: "k1", Secret: "not-base64!!", Status: KeyStatusActive}},
		"weak_secret":   {{KeyID: "k1", Secret: b64([]byte("short")), Status: KeyStatusActive}},
		"bad_status":    {{KeyID: "k1", Secret: b64(testSecret(1)), Status: "weird"}},
		"duplicate_ids": {{KeyID: "k1", Secret: b64(testSecret(1)), Status: KeyStatusActive}, {KeyID: "k1", Secret: b64(testSecret(2)), Status: KeyStatusPrevious}},
	}
	for name, keys := range cases {
		t.Run(name, func(t *testing.T) {
			writeKeyFile(t, dir, slug, keys)
			store := NewFileKeyStore(dir)
			if _, err := store.Keys(context.Background(), slug); !errors.Is(err, ErrKeyStoreUnavailable) {
				t.Fatalf("error = %v, want ErrKeyStoreUnavailable", err)
			}
		})
	}
}
