package toolauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// nonceBytes is the entropy of a per-request nonce (base64url encoded).
const nonceBytes = 32

// Signature is the set of values Core sends with a signed request.
type Signature struct {
	KeyID     string
	Timestamp string
	Nonce     string
	Value     string
	// Canonical is the exact string that was signed. It contains no secret
	// material and is retained so a streamed body digest can be bound to the
	// same request afterwards.
	Canonical string
}

// Apply writes the signature headers onto h. It always sets X-Gateway too, so a
// signed request can never be missing the caller identity header.
func (s Signature) Apply(h http.Header) {
	h.Set(HeaderGateway, GatewayIdentifier)
	h.Set(HeaderKeyID, s.KeyID)
	h.Set(HeaderTimestamp, s.Timestamp)
	h.Set(HeaderNonce, s.Nonce)
	h.Set(HeaderSignature, s.Value)
}

// Signer signs outbound Core -> Tool requests with the tool's active key.
type Signer struct {
	keys  KeyStore
	now   func() time.Time
	nonce func() (string, error)
}

// NewSigner returns a signer backed by store.
func NewSigner(store KeyStore) *Signer {
	return &Signer{
		keys:  store,
		now:   time.Now,
		nonce: generateNonce,
	}
}

// Sign produces the signature for one request.
//
// bodyHash must be BodyHash(body) for a fully known body, or BodyHashStreamed
// when the body is streamed; in the streamed case the caller must additionally
// send the signed digest trailer produced by SignDigestTrailer.
func (s *Signer) Sign(ctx context.Context, toolSlug, method, path, query, bodyHash string) (Signature, error) {
	if s == nil || s.keys == nil {
		return Signature{}, ErrKeyStoreUnavailable
	}
	if bodyHash == "" {
		bodyHash = EmptyBodySHA256
	}
	set, err := s.keys.Keys(ctx, toolSlug)
	if err != nil {
		return Signature{}, err
	}
	key, err := set.Active(s.now())
	if err != nil {
		return Signature{}, err
	}
	nonce, err := s.nonce()
	if err != nil {
		return Signature{}, fmt.Errorf("toolauth: generating nonce: %w", err)
	}
	timestamp := strconv.FormatInt(s.now().Unix(), 10)
	canonical := CanonicalString(method, path, query, key.ID, timestamp, nonce, bodyHash)
	return Signature{
		KeyID:     key.ID,
		Timestamp: timestamp,
		Nonce:     nonce,
		Value:     sign(key.Secret(), canonical),
		Canonical: canonical,
	}, nil
}

// SignDigestTrailer binds a streamed body's digest to an already-signed
// request. The tool verifies it against the bytes it actually received.
func (s *Signer) SignDigestTrailer(ctx context.Context, toolSlug string, sig Signature, digestValue string) (string, error) {
	if s == nil || s.keys == nil {
		return "", ErrKeyStoreUnavailable
	}
	set, err := s.keys.Keys(ctx, toolSlug)
	if err != nil {
		return "", err
	}
	key, ok := set.Lookup(sig.KeyID)
	if !ok {
		return "", ErrUnknownKey
	}
	return BodyDigestSignature(key.Secret(), sig.Canonical, digestValue), nil
}

// BodyDigestSignature is the signature a streamed request carries in its
// trailing header: HMAC over the canonical string plus the digest value.
func BodyDigestSignature(secret []byte, canonical, digestValue string) string {
	return sign(secret, canonical+"\n"+digestValue)
}

func sign(secret []byte, canonical string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

func generateNonce() (string, error) {
	buf := make([]byte, nonceBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// NewNonce returns a fresh cryptographically random nonce. Senders that build
// requests outside the Signer (tests, other languages) use the same format.
func NewNonce() (string, error) {
	return generateNonce()
}
