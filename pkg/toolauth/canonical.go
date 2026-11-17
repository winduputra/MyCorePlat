package toolauth

import (
	"crypto/sha256"
	"encoding/hex"
)

// CanonicalString builds the exact string that Core signs and a tool verifies.
//
// The fields are joined with "\n" in this order:
//
//	METHOD \n path \n query \n keyId \n timestamp \n nonce \n bodyHash
//
// Rules:
//   - METHOD is the upper-case HTTP method.
//   - path is the request path as sent on the wire (percent-encoding intact),
//     never a decoded or normalized form.
//   - query is the raw query string without the leading "?", and is the empty
//     string when the request has no query.
//   - timestamp is unix epoch seconds in decimal.
//   - bodyHash is the lowercase hex SHA-256 of the exact body bytes
//     (EmptyBodySHA256 for a bodyless request), or BodyHashStreamed when the
//     bytes are bound by the signed digest trailer instead.
//
// Any change to any field invalidates the signature.
func CanonicalString(method, path, query, keyID, timestamp, nonce, bodyHash string) string {
	return method + "\n" + path + "\n" + query + "\n" + keyID + "\n" + timestamp + "\n" + nonce + "\n" + bodyHash
}

// BodyHash returns the lowercase hex SHA-256 of b, the value used as bodyHash
// in the canonical string.
func BodyHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// StreamedDigest builds the digest value sent in the body-digest trailer for a
// streamed body: "sha-256=<lowercase hex>".
func StreamedDigest(body []byte) string {
	return "sha-256=" + BodyHash(body)
}
