package service

import (
	"strings"
	"testing"
)

// TestHashPasswordProducesVerifiableHash verifies a hash round-trips through
// verification and never equals the plaintext.
func TestHashPasswordProducesVerifiableHash(t *testing.T) {
	const plaintext = "correct horse battery staple"

	hash, err := HashPassword(plaintext)
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}
	if hash == "" {
		t.Fatal("HashPassword returned empty hash")
	}
	if hash == plaintext {
		t.Fatal("hash equals plaintext; password must never be stored in clear")
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("hash is not an argon2id PHC string: %q", hash)
	}

	ok, err := VerifyPassword(plaintext, hash)
	if err != nil {
		t.Fatalf("VerifyPassword returned error: %v", err)
	}
	if !ok {
		t.Fatal("VerifyPassword rejected the correct password")
	}
}

// TestHashPasswordProducesUniqueSalts ensures the same password hashes to
// different outputs (random salt per hash).
func TestHashPasswordProducesUniqueSalts(t *testing.T) {
	first, err := HashPassword("same-password")
	if err != nil {
		t.Fatalf("HashPassword error: %v", err)
	}
	second, err := HashPassword("same-password")
	if err != nil {
		t.Fatalf("HashPassword error: %v", err)
	}
	if first == second {
		t.Fatal("two hashes of the same password are identical; salt is not random")
	}
}

// TestVerifyPasswordRejectsWrongPassword ensures a different password fails.
func TestVerifyPasswordRejectsWrongPassword(t *testing.T) {
	hash, err := HashPassword("the-real-password")
	if err != nil {
		t.Fatalf("HashPassword error: %v", err)
	}

	ok, err := VerifyPassword("the-wrong-password", hash)
	if err != nil {
		// A wrong password must be a clean mismatch, not a parse error.
		t.Fatalf("VerifyPassword returned error on wrong password: %v", err)
	}
	if ok {
		t.Fatal("VerifyPassword accepted a wrong password")
	}
}

// TestVerifyPasswordRejectsMalformedHash ensures corrupt stored hashes fail
// closed rather than error-panicking or returning true.
func TestVerifyPasswordRejectsMalformedHash(t *testing.T) {
	for _, bad := range []string{"", "not-a-hash", "$argon2id$v=19$m=1$salt", "$2b$bad"} {
		ok, err := VerifyPassword("anything", bad)
		if err == nil && ok {
			t.Fatalf("VerifyPassword accepted malformed hash %q", bad)
		}
	}
}

// TestHashPasswordRejectsEmpty ensures empty plaintext is refused.
func TestHashPasswordRejectsEmpty(t *testing.T) {
	if _, err := HashPassword(""); err == nil {
		t.Fatal("HashPassword accepted an empty password")
	}
}
