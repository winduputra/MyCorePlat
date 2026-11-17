package service

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func newTestPreAuthCSRF() *PreAuthCSRFService {
	return NewPreAuthCSRFService([]byte("test-csrf-secret"), 10*time.Minute)
}

// TestPreAuthCSRFIssueAndVerify asserts a freshly issued token verifies.
func TestPreAuthCSRFIssueAndVerify(t *testing.T) {
	svc := newTestPreAuthCSRF()
	token, expiry, err := svc.Issue()
	if err != nil {
		t.Fatalf("Issue error: %v", err)
	}
	if token == "" {
		t.Fatal("Issue returned an empty token")
	}
	if !expiry.After(time.Now()) {
		t.Fatal("expiry is not in the future")
	}
	if err := svc.Verify(token); err != nil {
		t.Fatalf("Verify rejected a valid token: %v", err)
	}
}

// TestPreAuthCSRFEmptyTokenRejected asserts empty input is a distinct error.
func TestPreAuthCSRFEmptyTokenRejected(t *testing.T) {
	svc := newTestPreAuthCSRF()
	if err := svc.Verify(""); !errors.Is(err, ErrPreAuthCSRFMissing) {
		t.Fatalf("Verify(\"\") error = %v, want ErrPreAuthCSRFMissing", err)
	}
}

// TestPreAuthCSRFMalformedTokenRejected asserts structural garbage is refused.
func TestPreAuthCSRFMalformedTokenRejected(t *testing.T) {
	svc := newTestPreAuthCSRF()
	cases := []string{"abc", "a.b", "a.b.c.d", "....", "  "}
	for _, tok := range cases {
		if err := svc.Verify(tok); !errors.Is(err, ErrPreAuthCSRFInvalid) {
			t.Fatalf("Verify(%q) error = %v, want ErrPreAuthCSRFInvalid", tok, err)
		}
	}
}

// TestPreAuthCSRFExpiredRejected asserts expiry is enforced.
func TestPreAuthCSRFExpiredRejected(t *testing.T) {
	svc := NewPreAuthCSRFService([]byte("test-csrf-secret"), time.Minute)
	token, _, err := svc.Issue()
	if err != nil {
		t.Fatalf("Issue error: %v", err)
	}

	// Advance the clock past expiry without sleeping.
	svc.now = func() time.Time { return time.Now().Add(2 * time.Minute) }

	if err := svc.Verify(token); !errors.Is(err, ErrPreAuthCSRFExpired) {
		t.Fatalf("Verify of expired token error = %v, want ErrPreAuthCSRFExpired", err)
	}
}

// TestPreAuthCSRFTamperedRejected asserts any mutation invalidates the HMAC.
func TestPreAuthCSRFTamperedRejected(t *testing.T) {
	svc := newTestPreAuthCSRF()
	token, _, err := svc.Issue()
	if err != nil {
		t.Fatalf("Issue error: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected token structure: %q", token)
	}

	// Flip a character in each of the three segments in turn.
	tampered := map[string]string{
		"nonce":     "A" + parts[0][1:] + "." + parts[1] + "." + parts[2],
		"expiry":    parts[0] + "." + parts[1] + "9" + "." + parts[2],
		"signature": parts[0] + "." + parts[1] + "." + flipLast(parts[2]),
	}
	for name, tok := range tampered {
		if tok == token {
			continue // no-op mutation (e.g. already ended in the flipped char)
		}
		if err := svc.Verify(tok); !errors.Is(err, ErrPreAuthCSRFInvalid) && !errors.Is(err, ErrPreAuthCSRFExpired) {
			t.Fatalf("Verify(tampered %s) error = %v, want invalid/expired", name, err)
		}
	}
}

// TestPreAuthCSRFWrongSecretRejected asserts a token signed with a different
// secret (i.e. attacker-forged) does not verify under the real secret.
func TestPreAuthCSRFWrongSecretRejected(t *testing.T) {
	attacker := NewPreAuthCSRFService([]byte("attacker-secret"), 10*time.Minute)
	forged, _, err := attacker.Issue()
	if err != nil {
		t.Fatalf("Issue error: %v", err)
	}

	victim := NewPreAuthCSRFService([]byte("real-server-secret"), 10*time.Minute)
	if err := victim.Verify(forged); !errors.Is(err, ErrPreAuthCSRFInvalid) {
		t.Fatalf("Verify(attacker token) error = %v, want ErrPreAuthCSRFInvalid", err)
	}
}

// TestPreAuthCSRFTokensAreUnique asserts two issues differ (random nonce).
func TestPreAuthCSRFTokensAreUnique(t *testing.T) {
	svc := newTestPreAuthCSRF()
	a, _, err := svc.Issue()
	if err != nil {
		t.Fatalf("Issue error: %v", err)
	}
	b, _, err := svc.Issue()
	if err != nil {
		t.Fatalf("Issue error: %v", err)
	}
	if a == b {
		t.Fatal("two issued tokens are identical; nonce is not random")
	}
}

func flipLast(s string) string {
	if s == "" {
		return "x"
	}
	last := s[len(s)-1]
	replacement := byte('A')
	if last == 'A' {
		replacement = 'B'
	}
	return s[:len(s)-1] + string(replacement)
}
