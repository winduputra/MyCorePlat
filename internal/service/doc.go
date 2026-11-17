// Package service holds business logic: authentication, session lifecycle,
// CSRF, rate limiting, token lifecycle, tool status, and authorization
// decisions. It is independent of HTTP and of the database driver so it can be
// unit-tested without a running server. Security primitives live here because
// they are security-sensitive business rules shared across handlers.
package service
