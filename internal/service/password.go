package service

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// ErrEmptyPassword is returned when a blank password is supplied.
var ErrEmptyPassword = errors.New("password must not be empty")

// Argon2id tuning. These defaults target the documented baseline
// (memory >= 64 MB, iterations >= 3). They are package-level so tests can
// reason about them and a future task can make them configurable.
const (
	argon2Time    = 3
	argon2Memory  = 64 * 1024 // 64 MiB, in KiB as required by argon2.IDKey
	argon2Threads = 4
	argon2KeyLen  = 32
	argon2SaltLen = 16
)

// HashPassword derives an Argon2id hash of plaintext and returns it encoded as
// a PHC string ("$argon2id$v=19$m=...,t=...,p=...$salt$hash"). The plaintext is
// never stored. An empty password is rejected.
func HashPassword(plaintext string) (string, error) {
	if plaintext == "" {
		return "", ErrEmptyPassword
	}

	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(plaintext), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	// PHC encoding: b64 is raw (unpadded) standard base64 without padding.
	b64 := base64.RawStdEncoding
	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argon2Memory, argon2Time, argon2Threads,
		b64.EncodeToString(salt), b64.EncodeToString(hash),
	)
	return encoded, nil
}

// VerifyPassword reports whether plaintext matches the stored PHC hash. It uses
// a constant-time comparison and fails closed on malformed hashes.
func VerifyPassword(plaintext, encoded string) (bool, error) {
	params, salt, want, err := decodeArgon2id(encoded)
	if err != nil {
		return false, err
	}

	got := argon2.IDKey([]byte(plaintext), salt, params.time, params.memory, params.threads, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) == 1 {
		return true, nil
	}
	return false, nil
}

// argon2Params holds the cost parameters read from a PHC string.
type argon2Params struct {
	memory  uint32
	time    uint32
	threads uint8
}

// decodeArgon2id parses an Argon2id PHC string into its parameters, salt, and
// expected hash bytes.
func decodeArgon2id(encoded string) (argon2Params, []byte, []byte, error) {
	var p argon2Params

	parts := strings.Split(encoded, "$")
	// Expected: ["", "argon2id", "v=19", "m=...,t=...,p=...", salt, hash]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return p, nil, nil, errors.New("invalid argon2id hash format")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return p, nil, nil, errors.New("invalid argon2id version")
	}
	if version != argon2.Version {
		return p, nil, nil, fmt.Errorf("unsupported argon2id version %d", version)
	}

	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.time, &p.threads); err != nil {
		return p, nil, nil, errors.New("invalid argon2id parameters")
	}

	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return p, nil, nil, errors.New("invalid argon2id salt")
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil {
		return p, nil, nil, errors.New("invalid argon2id hash")
	}
	if len(salt) == 0 || len(want) == 0 {
		return p, nil, nil, errors.New("empty argon2id salt or hash")
	}

	return p, salt, want, nil
}
