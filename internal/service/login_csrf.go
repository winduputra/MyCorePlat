package service

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Pre-auth CSRF error sentinels. Callers use errors.Is to distinguish causes
// without depending on message strings.
var (
	ErrPreAuthCSRFMissing = errors.New("pre-auth csrf token missing")
	ErrPreAuthCSRFInvalid = errors.New("pre-auth csrf token invalid")
	ErrPreAuthCSRFExpired = errors.New("pre-auth csrf token expired")
)

// PreAuthCSRFToken is a signed double-submit CSRF token used to protect the
// login form before a session exists. Its wire format is:
//
//	base64url(nonce) "." base64url(unix-expiry) "." base64url(hmacSHA256)
//
// The cookie carries this full signed value, and the login form carries the
// same value in a hidden field. Because the value is HMAC-signed with a
// server-side secret, an attacker cannot forge or tamper with it, so an injected
// cookie cannot be paired with a matching form token.
type PreAuthCSRFService struct {
	secret []byte
	ttl    time.Duration
	now    func() time.Time
}

// NewPreAuthCSRFService constructs the service. secret must be non-empty; ttl
// bounds token lifetime.
func NewPreAuthCSRFService(secret []byte, ttl time.Duration) *PreAuthCSRFService {
	return &PreAuthCSRFService{
		secret: secret,
		ttl:    ttl,
		now:    time.Now,
	}
}

// Issue mints a fresh signed token valid for the configured TTL.
func (s *PreAuthCSRFService) Issue() (string, time.Time, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return "", time.Time{}, fmt.Errorf("generate pre-auth csrf nonce: %w", err)
	}
	expiry := s.now().Add(s.ttl)
	payload := encodeNonce(nonce) + "." + strconv.FormatInt(expiry.Unix(), 10)
	sig := s.sign(payload)
	return payload + "." + sig, expiry, nil
}

// Verify checks the structure, expiry, and HMAC of a token. It returns
// ErrPreAuthCSRFMissing for an empty token, ErrPreAuthCSRFExpired when the
// token has passed its expiry, and ErrPreAuthCSRFInvalid for any structural or
// signature problem. Expiry is still checked before the HMAC so that a token
// with a well-formed signature but stale timestamp is reported as expired;
// the HMAC is verified regardless to keep the failure free of timing bias.
func (s *PreAuthCSRFService) Verify(token string) error {
	if token == "" {
		return ErrPreAuthCSRFMissing
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ErrPreAuthCSRFInvalid
	}
	payload := parts[0] + "." + parts[1]
	expectedSig := s.sign(payload)

	// Constant-time signature comparison first.
	if subtle.ConstantTimeCompare([]byte(expectedSig), []byte(parts[2])) != 1 {
		return ErrPreAuthCSRFInvalid
	}

	expiryUnix, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return ErrPreAuthCSRFInvalid
	}
	if !s.now().Before(time.Unix(expiryUnix, 0)) {
		return ErrPreAuthCSRFExpired
	}
	return nil
}

// sign returns the base64url HMAC-SHA256 of payload under the service secret.
func (s *PreAuthCSRFService) sign(payload string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func encodeNonce(nonce []byte) string {
	return base64.RawURLEncoding.EncodeToString(nonce)
}
