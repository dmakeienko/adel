package middleware

import (
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// RateLimitConfig configures a RateLimit middleware instance.
type RateLimitConfig struct {
	// Requests is the sustained number of requests allowed per Window. A value of
	// zero or less disables the limiter entirely.
	Requests int
	// Window is the period over which Requests is replenished.
	Window time.Duration
	// Burst is the maximum number of requests that may be spent at once. Zero
	// defaults to Requests, giving a plain "N per window" allowance.
	Burst int
}

// tokenBucket is a single actor's allowance. Tokens are not replenished by a
// background ticker; instead each visit computes how many have accrued since the
// last one, so an idle bucket costs nothing until it is used again.
type tokenBucket struct {
	tokens   float64
	lastSeen time.Time
}

// rateLimiter hands out and ages token buckets keyed by actor.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket

	burst      float64
	refillRate float64 // tokens per second
	window     time.Duration

	// now is time.Now in production and a stub in tests, so the limiter's
	// refill behavior can be exercised without sleeping.
	now func() time.Time
}

func newRateLimiter(cfg RateLimitConfig) *rateLimiter {
	burst := cfg.Burst
	if burst <= 0 {
		burst = cfg.Requests
	}

	return &rateLimiter{
		buckets:    make(map[string]*tokenBucket),
		burst:      float64(burst),
		refillRate: float64(cfg.Requests) / cfg.Window.Seconds(),
		window:     cfg.Window,
		now:        time.Now,
	}
}

// allow spends a token for key, reporting whether one was available and, if not,
// how long the caller should wait before retrying.
func (l *rateLimiter) allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	bucket, ok := l.buckets[key]
	if !ok {
		// A previously unseen actor starts with a full allowance, minus this request.
		l.buckets[key] = &tokenBucket{tokens: l.burst - 1, lastSeen: now}
		return true, 0
	}

	// Accrue the tokens earned since the last request, capped at burst.
	bucket.tokens += now.Sub(bucket.lastSeen).Seconds() * l.refillRate
	if bucket.tokens > l.burst {
		bucket.tokens = l.burst
	}
	bucket.lastSeen = now

	if bucket.tokens < 1 {
		// Report the wait until a single whole token is available.
		retryAfter := time.Duration((1-bucket.tokens)/l.refillRate) * time.Second
		if retryAfter < time.Second {
			retryAfter = time.Second
		}
		return false, retryAfter
	}

	bucket.tokens--
	return true, 0
}

// evictIdle drops buckets that have been full and untouched for longer than the
// eviction age, bounding memory for one-off actors. A bucket is only removed once
// it has fully refilled, so dropping it cannot hand back an unearned allowance.
func (l *rateLimiter) evictIdle(maxIdle time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := l.now().Add(-maxIdle)
	for key, bucket := range l.buckets {
		if bucket.lastSeen.Before(cutoff) {
			delete(l.buckets, key)
		}
	}
}

// RateLimit returns middleware that throttles requests per authenticated user,
// falling back to the client IP for unauthenticated ones. It is intended for
// sensitive endpoints; the returned middleware is safe for concurrent use.
//
// A non-positive Requests value disables throttling and returns a pass-through,
// so the feature can be turned off by configuration without changing the routes.
func RateLimit(cfg RateLimitConfig) func(http.Handler) http.Handler {
	if cfg.Requests <= 0 || cfg.Window <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}

	limiter := newRateLimiter(cfg)

	// Age out idle buckets so a long-lived process does not accumulate one entry
	// per actor forever. The interval is tied to the window rather than fixed, so
	// a generous window does not get swept prematurely.
	evictEvery := cfg.Window
	if evictEvery < time.Minute {
		evictEvery = time.Minute
	}
	go func() {
		for range time.Tick(evictEvery) {
			limiter.evictIdle(2 * evictEvery)
		}
	}()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := rateLimitKey(r)

			allowed, retryAfter := limiter.allow(key)
			if !allowed {
				slog.Warn("Rate limit exceeded", //nolint:gosec // G706: structured logging with key-value pairs, not string interpolation
					"actor", key,
					"method", r.Method,
					"path", r.URL.Path,
					"retry_after", retryAfter.String(),
				)
				w.Header().Set("Retry-After", intToString(int(retryAfter.Seconds())))
				w.WriteHeader(http.StatusTooManyRequests)
				// Content-Type is already application/json via the JSON middleware.
				_, _ = w.Write([]byte(`{"success":false,"error":"Too many requests, please slow down"}`))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// rateLimitKey identifies the actor to throttle. The authenticated username is
// preferred so a caller cannot reset their budget by changing source address;
// unauthenticated requests fall back to the peer IP.
func rateLimitKey(r *http.Request) string {
	if sess := GetSessionFromContext(r.Context()); sess != nil && sess.Username != "" {
		return "user:" + sess.Username
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return "ip:" + host
}
