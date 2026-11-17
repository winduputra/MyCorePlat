package service

import (
	"crypto/subtle"
)

// ValidateCSRF compares the session's stored CSRF token with the token supplied
// by the client. It fails closed: an empty expected or supplied token never
// validates, and comparison is constant-time to avoid leaking the token via
// timing.
func ValidateCSRF(expected, supplied string) bool {
	if expected == "" || supplied == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(supplied)) == 1
}
