package service

import (
	"testing"
)

// TestValidateCSRFAcceptsMatching asserts a matching token passes.
func TestValidateCSRFAcceptsMatching(t *testing.T) {
	token := "csrf-token-value"
	if !ValidateCSRF(token, token) {
		t.Fatal("ValidateCSRF rejected a matching token")
	}
}

// TestValidateCSRFRejectsMismatch asserts a wrong token is refused.
func TestValidateCSRFRejectsMismatch(t *testing.T) {
	if ValidateCSRF("expected-token", "supplied-token") {
		t.Fatal("ValidateCSRF accepted a mismatched token")
	}
}

// TestValidateCSRFRejectsMissing asserts empty supplied token is refused even
// when the session has one.
func TestValidateCSRFRejectsMissing(t *testing.T) {
	if ValidateCSRF("expected-token", "") {
		t.Fatal("ValidateCSRF accepted an empty token")
	}
}

// TestValidateCSRFRejectsEmptyExpected ensures a session with no CSRF token
// cannot be satisfied by an empty supplied token (fails closed).
func TestValidateCSRFRejectsEmptyExpected(t *testing.T) {
	if ValidateCSRF("", "") {
		t.Fatal("ValidateCSRF accepted empty/empty (should fail closed)")
	}
}

// TestValidateCSRFTimingSafeLengthMismatch confirms different-length tokens are
// rejected without panicking.
func TestValidateCSRFTimingSafeLengthMismatch(t *testing.T) {
	if ValidateCSRF("short", "a-much-longer-token") {
		t.Fatal("ValidateCSRF accepted tokens of different lengths")
	}
}
