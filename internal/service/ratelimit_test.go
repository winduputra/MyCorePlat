package service

import (
	"testing"
	"time"
)

// fixedClock lets tests advance time deterministically without sleeping.
type fixedClock struct {
	now time.Time
}

func (c *fixedClock) Now() time.Time          { return c.now }
func (c *fixedClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

func newTestLimiter(limit int, window time.Duration) (*RateLimiter, *fixedClock) {
	clock := &fixedClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	rl := NewRateLimiter(RateLimiterConfig{Limit: limit, Window: window})
	rl.now = clock.Now
	return rl, clock
}

// TestRateLimiterAllowsUpToLimit asserts the first N attempts are allowed.
func TestRateLimiterAllowsUpToLimit(t *testing.T) {
	rl, _ := newTestLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !rl.Allow("login:1.2.3.4") {
			t.Fatalf("attempt %d was blocked before reaching the limit", i+1)
		}
	}
}

// TestRateLimiterBlocksOverLimit asserts attempt N+1 is blocked.
func TestRateLimiterBlocksOverLimit(t *testing.T) {
	rl, _ := newTestLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		rl.Allow("login:1.2.3.4")
	}
	if rl.Allow("login:1.2.3.4") {
		t.Fatal("attempt N+1 was allowed; rate limit did not trigger")
	}
}

// TestRateLimiterResetsAfterWindow asserts the window slides and old attempts
// no longer count once it elapses.
func TestRateLimiterResetsAfterWindow(t *testing.T) {
	rl, clock := newTestLimiter(2, time.Minute)
	rl.Allow("k")
	rl.Allow("k")
	if rl.Allow("k") {
		t.Fatal("third attempt should be blocked within the window")
	}
	clock.Advance(61 * time.Second)
	if !rl.Allow("k") {
		t.Fatal("attempt after window elapsed should be allowed")
	}
}

// TestRateLimiterIsolatesKeys asserts limits are tracked per key, so one client
// exhausting its budget does not block another.
func TestRateLimiterIsolatesKeys(t *testing.T) {
	rl, _ := newTestLimiter(1, time.Minute)
	if !rl.Allow("a") {
		t.Fatal("first key should be allowed")
	}
	if rl.Allow("a") {
		t.Fatal("first key should now be blocked")
	}
	if !rl.Allow("b") {
		t.Fatal("a different key must not inherit the first key's block")
	}
}

// TestRateLimiterPersistsStateAcrossCalls documents that state is retained
// between Allow calls (i.e. not a fresh per-request object).
func TestRateLimiterPersistsStateAcrossCalls(t *testing.T) {
	rl, _ := newTestLimiter(1, time.Minute)
	first := rl.Allow("persist")
	second := rl.Allow("persist")
	if !first || second {
		t.Fatalf("state did not persist: first=%v second=%v", first, second)
	}
}
