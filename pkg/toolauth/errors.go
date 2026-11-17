package toolauth

import "errors"

// Verification and signing failures. Callers reject the request on any error;
// the messages never contain secret material.
var (
	// ErrMissingSignature means one or more signature headers are absent or
	// syntactically unusable.
	ErrMissingSignature = errors.New("toolauth: missing or malformed signature headers")
	// ErrUnknownKey means the key id is not provisioned for this tool.
	ErrUnknownKey = errors.New("toolauth: unknown signing key id")
	// ErrRevokedKey means the key id exists but has been revoked.
	ErrRevokedKey = errors.New("toolauth: signing key has been revoked")
	// ErrKeyExpired means a (typically "previous") key is past its notAfter
	// deadline and may no longer be accepted.
	ErrKeyExpired = errors.New("toolauth: signing key has expired")
	// ErrNoActiveKey means the key set has no usable active key to sign with.
	ErrNoActiveKey = errors.New("toolauth: no active signing key")
	// ErrSignatureMismatch means the HMAC did not match the request.
	ErrSignatureMismatch = errors.New("toolauth: signature mismatch")
	// ErrTimestampOutOfRange means the timestamp is older or newer than the
	// accepted clock-skew window.
	ErrTimestampOutOfRange = errors.New("toolauth: timestamp outside allowed skew window")
	// ErrBodyHashMismatch means the received body does not match the signed hash.
	ErrBodyHashMismatch = errors.New("toolauth: body hash does not match signature")
	// ErrStreamedDigestMissing means a streamed request did not deliver the
	// signed digest trailer, so body integrity cannot be proven.
	ErrStreamedDigestMissing = errors.New("toolauth: signed body digest trailer missing")
	// ErrNonceReused means this key id has already accepted this nonce.
	ErrNonceReused = errors.New("toolauth: nonce already used")
	// ErrNonceStoreUnavailable means replay protection could not be consulted.
	// Callers MUST fail closed: never process a request without it.
	ErrNonceStoreUnavailable = errors.New("toolauth: replay protection unavailable")
	// ErrKeyStoreUnavailable means the configured key source could not be read.
	ErrKeyStoreUnavailable = errors.New("toolauth: key store unavailable")
	// ErrKeyNotFound means no key material is provisioned for the tool.
	ErrKeyNotFound = errors.New("toolauth: no key provisioned for tool")
)
