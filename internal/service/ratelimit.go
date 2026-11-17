package service

import (
	"sync"
	"time"
)

// RateLimiterConfig configures a sliding-window limiter.
type RateLimiterConfig struct {
	// Limit is the maximum number of allowed events per key per window.
	Limit int
	// Window is the sliding window duration.
	Window time.Duration
}

// RateLimiter is an in-memory sliding-window rate limiter keyed by an arbitrary
// string (e.g. "login:<ip>" or "login:<username>"). It retains state across
// requests, which is essential — a per-request limiter would enforce nothing.
// It is safe for concurrent use. State is intentionally not persisted: restart
// clears counters, which is acceptable for brute-force throttling in the admin
// login path.
type RateLimiter struct {
	limit  int
	window time.Duration
	// now is injectable for deterministic tests; defaults to time.Now.
	now func() time.Time

	mu      sync.Mutex
	buckets map[string][]time.Time
}

// NewRateLimiter builds a limiter from config. A non-positive limit disables
// limiting (allows everything), which callers may use for tests/dev.
func NewRateLimiter(cfg RateLimiterConfig) *RateLimiter {
	return &RateLimiter{
		limit:   cfg.Limit,
		window:  cfg.Window,
		now:     time.Now,
		buckets: make(map[string][]time.Time),
	}
}

// Allow records an attempt for key and reports whether it is permitted. When the
// limit is exceeded the attempt is ALSO counted (so sustained abuse keeps the
// key blocked) but the return value is false.
func (r *RateLimiter) Allow(key string) bool {
	if r.limit <= 0 {
		return true
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now()
	cutoff := now.Add(-r.window)

	// Drop timestamps that fell out of the window.
	times := r.buckets[key]
	pruned := times[:0]
	for _, ts := range times {
		if ts.After(cutoff) {
			pruned = append(pruned, ts)
		}
	}

	allowed := len(pruned) < r.limit
	// Count this attempt regardless, so repeated blocked attempts keep the
	// window populated and the key stays throttled under sustained attack.
	pruned = append(pruned, now)
	r.buckets[key] = pruned

	return allowed
}

// Reset clears the counters for a key (e.g. after a successful login).
func (r *RateLimiter) Reset(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.buckets, key)
}
