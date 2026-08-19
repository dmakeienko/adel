package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"adel/session"
)

// okHandler counts the requests that make it past the limiter.
func okHandler(calls *int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*calls++
		w.WriteHeader(http.StatusOK)
	})
}

// requestAs builds a request carrying a session for the given username, so the
// limiter keys on the user rather than the source address.
func requestAs(username string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/target/reset-password", nil)
	if username == "" {
		return req
	}
	sess := &session.Session{Username: username}
	return req.WithContext(context.WithValue(req.Context(), SessionContextKey, sess))
}

func TestRateLimitAllowsUpToBurstThenRejects(t *testing.T) {
	calls := 0
	handler := RateLimit(RateLimitConfig{Requests: 3, Window: time.Minute})(okHandler(&calls))

	for i := 1; i <= 3; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, requestAs("operator"))
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want %d", i, rr.Code, http.StatusOK)
		}
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, requestAs("operator"))

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("4th request: status = %d, want %d", rr.Code, http.StatusTooManyRequests)
	}
	if calls != 3 {
		t.Errorf("handler calls = %d, want 3", calls)
	}
	if retryAfter := rr.Header().Get("Retry-After"); retryAfter == "" {
		t.Error("Retry-After header is not set on a throttled response")
	}
}

func TestRateLimitIsPerUser(t *testing.T) {
	calls := 0
	handler := RateLimit(RateLimitConfig{Requests: 1, Window: time.Minute})(okHandler(&calls))

	// Spend the first user's entire allowance.
	handler.ServeHTTP(httptest.NewRecorder(), requestAs("operator"))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, requestAs("operator"))
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("operator second request: status = %d, want %d", rr.Code, http.StatusTooManyRequests)
	}

	// A different user must be unaffected by the first user's exhaustion.
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, requestAs("другой"))
	if rr.Code != http.StatusOK {
		t.Errorf("second user: status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestRateLimitFallsBackToIPWhenUnauthenticated(t *testing.T) {
	handler := RateLimit(RateLimitConfig{Requests: 1, Window: time.Minute})(okHandler(new(int)))

	// Both requests share httptest's default RemoteAddr, so they share a bucket.
	handler.ServeHTTP(httptest.NewRecorder(), requestAs(""))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, requestAs(""))

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusTooManyRequests)
	}
}

func TestRateLimitRefillsOverTime(t *testing.T) {
	limiter := newRateLimiter(RateLimitConfig{Requests: 2, Window: time.Minute})
	current := time.Now()
	limiter.now = func() time.Time { return current }

	// Drain the bucket.
	for i := 0; i < 2; i++ {
		if allowed, _ := limiter.allow("user:operator"); !allowed {
			t.Fatalf("request %d denied while allowance remained", i+1)
		}
	}
	if allowed, retryAfter := limiter.allow("user:operator"); allowed {
		t.Fatal("request allowed after the allowance was spent")
	} else if retryAfter <= 0 {
		t.Errorf("retryAfter = %v, want a positive wait", retryAfter)
	}

	// Two per minute means one token accrues after thirty seconds.
	current = current.Add(30 * time.Second)
	if allowed, _ := limiter.allow("user:operator"); !allowed {
		t.Error("request denied after a token should have refilled")
	}
}

func TestRateLimitDisabledWhenRequestsNonPositive(t *testing.T) {
	calls := 0
	handler := RateLimit(RateLimitConfig{Requests: 0, Window: time.Minute})(okHandler(&calls))

	for i := 0; i < 50; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, requestAs("operator"))
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want %d with the limiter disabled", i, rr.Code, http.StatusOK)
		}
	}
	if calls != 50 {
		t.Errorf("handler calls = %d, want 50", calls)
	}
}

func TestRateLimitEvictsIdleBuckets(t *testing.T) {
	limiter := newRateLimiter(RateLimitConfig{Requests: 5, Window: time.Minute})
	current := time.Now()
	limiter.now = func() time.Time { return current }

	limiter.allow("user:operator")
	if len(limiter.buckets) != 1 {
		t.Fatalf("buckets = %d, want 1", len(limiter.buckets))
	}

	// Not yet past the idle age, so the bucket is retained.
	current = current.Add(30 * time.Second)
	limiter.evictIdle(time.Minute)
	if len(limiter.buckets) != 1 {
		t.Errorf("buckets = %d, want the bucket retained before the idle age", len(limiter.buckets))
	}

	current = current.Add(2 * time.Minute)
	limiter.evictIdle(time.Minute)
	if len(limiter.buckets) != 0 {
		t.Errorf("buckets = %d, want the idle bucket evicted", len(limiter.buckets))
	}
}

// TestRateLimitConcurrentAccess exercises the limiter from many goroutines so the
// race detector can catch unsynchronized access to the bucket map.
func TestRateLimitConcurrentAccess(t *testing.T) {
	// A no-op terminal handler: this test is about the limiter's internal locking,
	// so it deliberately avoids a shared counter that would itself race.
	handler := RateLimit(RateLimitConfig{Requests: 100, Window: time.Minute})(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
	)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			handler.ServeHTTP(httptest.NewRecorder(), requestAs("operator"))
		}()
	}
	wg.Wait()
}
