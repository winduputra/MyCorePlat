// Package toolauth implements the internal Core -> Tool request signature
// described in docs/architecture.md §4.4 and docs/tool-integration.md §4.5.
//
// Core signs every proxied request with an HMAC-SHA256 signature using a
// secret that is unique per tool; the tool verifies the signature, the clock
// skew window, the key id, the body integrity, and the nonce before it
// processes anything.
//
// Canonical string (deterministic, fields joined with a single "\n"):
//
//	METHOD \n path \n query \n keyId \n timestamp \n nonce \n bodyHash
//
// Signature = lowercase hex HMAC-SHA256(secret, canonicalString).
//
// This package contains no transport or storage policy of its own: the secret
// source is a KeyStore and the replay store is a NonceStore, so Core can read
// keys from provisioned secret files and tools can plug the shared store that
// fits their deployment.
package toolauth

import "time"

const (
	// HeaderGateway identifies the logical caller. Informational only.
	HeaderGateway = "X-Gateway"
	// HeaderSignature carries the hex HMAC-SHA256 signature.
	HeaderSignature = "X-Signature"
	// HeaderKeyID identifies which secret was used to sign.
	HeaderKeyID = "X-Signature-Key-Id"
	// HeaderTimestamp is the unix epoch second at signing time.
	HeaderTimestamp = "X-Signature-Timestamp"
	// HeaderNonce is the cryptographically random per-request value.
	HeaderNonce = "X-Signature-Nonce"
	// HeaderBodyDigest is the trailer carrying "sha-256=<hex>" for streamed
	// bodies (RFC 9530 style digest value).
	HeaderBodyDigest = "X-Signature-Body-Digest"
	// HeaderBodySignature is the trailer-carrying signature over the canonical
	// string plus the digest value, binding the streamed bytes to the request.
	HeaderBodySignature = "X-Signature-Body-Sig"

	// GatewayIdentifier is the value Core sends in HeaderGateway.
	GatewayIdentifier = "tools-bpbj-core"

	// BodyHashStreamed replaces the body hash in the canonical string for
	// requests whose body is streamed: the actual bytes are bound by the signed
	// digest trailer instead of being known before the headers are sent.
	BodyHashStreamed = "streamed"

	// EmptyBodySHA256 is the lowercase hex SHA-256 of an empty body.
	EmptyBodySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	// DefaultSkew is the accepted clock-skew window when a Verifier does not
	// configure one.
	DefaultSkew = 60 * time.Second
	// DefaultNonceTTL is used when a Verifier does not configure one. It must
	// stay at least twice the accepted skew window.
	DefaultNonceTTL = 2 * time.Minute
)
