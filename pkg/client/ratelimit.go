package client

import (
	"context"
	"math/rand"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter controls request rate to avoid WAF detection and bans
type RateLimiter struct {
	limiter  *rate.Limiter
	minDelay time.Duration
	maxDelay time.Duration
	jitter   bool
}

// NewRateLimiter creates a new rate limiter
// requestsPerSecond: max requests per second
// minDelay: minimum delay between requests
// maxDelay: maximum delay for jitter (if enabled)
func NewRateLimiter(requestsPerSecond int, minDelay, maxDelay time.Duration) *RateLimiter {
	return &RateLimiter{
		limiter:  rate.NewLimiter(rate.Limit(requestsPerSecond), 1),
		minDelay: minDelay,
		maxDelay: maxDelay,
		jitter:   maxDelay > minDelay,
	}
}

// Wait blocks until a request can be made, respecting rate limits
func (rl *RateLimiter) Wait(ctx context.Context) error {
	// Wait for token from rate limiter
	if err := rl.limiter.Wait(ctx); err != nil {
		return err
	}

	// Apply delay with optional jitter
	delay := rl.minDelay
	if rl.jitter {
		jitterRange := rl.maxDelay - rl.minDelay
		delay = rl.minDelay + time.Duration(rand.Int63n(int64(jitterRange)))
	}

	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

// SetRate updates the rate limit dynamically
func (rl *RateLimiter) SetRate(requestsPerSecond int) {
	rl.limiter.SetLimit(rate.Limit(requestsPerSecond))
}
