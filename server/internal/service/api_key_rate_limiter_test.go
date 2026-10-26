package service

import (
	"context"
	"errors"
	"sort"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"ManScan/server/internal/model/dto"
)

type rateLimitSourceFunc func(context.Context, int64) (*dto.ThirdPartyAPIKeyListItem, error)

func (f rateLimitSourceFunc) Get(ctx context.Context, id int64) (*dto.ThirdPartyAPIKeyListItem, error) {
	return f(ctx, id)
}

func fixedRateLimitSource(limit uint32) APIKeyRateLimitSource {
	return rateLimitSourceFunc(func(context.Context, int64) (*dto.ThirdPartyAPIKeyListItem, error) {
		return &dto.ThirdPartyAPIKeyListItem{RateLimitPerMinute: limit}, nil
	})
}

func TestAPIKeyRateLimiterConcurrentRequestsShareBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const limit, requests = 3, 10
		limiter := NewAPIKeyRateLimiter(fixedRateLimitSource(limit))
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		results := make(chan time.Time, requests)
		for range requests {
			go func() {
				if err := limiter.Wait(ctx, 101); err != nil {
					t.Errorf("Wait() error = %v", err)
				}
				results <- time.Now()
			}()
		}
		times := make([]time.Time, 0, requests)
		for range requests {
			times = append(times, <-results)
		}
		sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
		for i := 1; i < len(times); i++ {
			if delta := times[i].Sub(times[i-1]); delta < time.Minute/limit {
				t.Fatalf("concurrent requests %d/%d are only %v apart", i-1, i, delta)
			}
		}
		for i := limit; i < len(times); i++ {
			if times[i].Sub(times[i-limit]) < time.Minute {
				t.Fatal("more than the configured budget admitted in a rolling minute")
			}
		}
	})
}

func TestAPIKeyRateLimiterCancellationDoesNotReserveQuota(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		limiter := NewAPIKeyRateLimiter(fixedRateLimitSource(1))
		started := time.Now()
		if err := limiter.Wait(context.Background(), 101); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() { result <- limiter.Wait(ctx, 101) }()
		synctest.Wait()
		// A different key must remain available while key 101 is waiting.
		if err := limiter.Wait(context.Background(), 102); err != nil || !time.Now().Equal(started) {
			t.Fatalf("another key was blocked: %v", err)
		}
		cancel()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("waiting cancellation = %v", err)
		}
		if err := limiter.Wait(context.Background(), 101); err != nil {
			t.Fatal(err)
		}
		if elapsed := time.Since(started); elapsed != time.Minute {
			t.Fatalf("canceled waiter reserved future quota: elapsed = %v", elapsed)
		}
		deadlineCtx, deadlineCancel := context.WithTimeout(context.Background(), time.Second)
		defer deadlineCancel()
		if err := limiter.Wait(deadlineCtx, 101); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("waiting timeout = %v", err)
		}
		if err := limiter.Wait(context.Background(), 101); err != nil {
			t.Fatal(err)
		}
		if elapsed := time.Since(started); elapsed != 2*time.Minute {
			t.Fatalf("timed-out waiter reserved future quota: elapsed = %v", elapsed)
		}
	})
}

func TestAPIKeyRateLimiterReloadsConfiguration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var limit atomic.Uint32
		limit.Store(60)
		source := rateLimitSourceFunc(func(context.Context, int64) (*dto.ThirdPartyAPIKeyListItem, error) {
			return &dto.ThirdPartyAPIKeyListItem{RateLimitPerMinute: limit.Load()}, nil
		})
		limiter := NewAPIKeyRateLimiter(source)
		started := time.Now()
		if err := limiter.Wait(context.Background(), 101); err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() { result <- limiter.Wait(context.Background(), 101) }()
		synctest.Wait()
		limit.Store(30)
		if err := <-result; err != nil {
			t.Fatal(err)
		}
		if elapsed := time.Since(started); elapsed != 2*time.Second {
			t.Fatalf("waiter used the old limit: elapsed = %v", elapsed)
		}
		limit.Store(0)
		before := time.Now()
		for range 10 {
			if err := limiter.Wait(context.Background(), 101); err != nil {
				t.Fatal(err)
			}
		}
		if !time.Now().Equal(before) {
			t.Fatal("zero-limit requests were delayed")
		}
	})
}

func TestAPIKeyRateLimiterRoundsIntervalUp(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		limiter := NewAPIKeyRateLimiter(fixedRateLimitSource(^uint32(0)))
		started := time.Now()
		for range 2 {
			if err := limiter.Wait(context.Background(), 101); err != nil {
				t.Fatal(err)
			}
		}
		if elapsed := time.Since(started); elapsed != 14*time.Nanosecond {
			t.Fatalf("maximum uint32 limit interval = %v, want 14ns rounded up", elapsed)
		}
	})
}

func TestAPIKeyRateLimiterRejectsInvalidConfiguration(t *testing.T) {
	missing := errors.New("API key no longer exists")
	for _, test := range []struct {
		name   string
		source APIKeyRateLimitSource
		keyID  int64
		want   error
	}{
		{name: "invalid ID", source: fixedRateLimitSource(1), keyID: 0, want: ErrInvalidThirdPartyAPIKey},
		{name: "missing service", keyID: 101},
		{name: "deleted key", keyID: 101, want: missing, source: rateLimitSourceFunc(func(context.Context, int64) (*dto.ThirdPartyAPIKeyListItem, error) {
			return nil, missing
		})},
		{name: "empty metadata", keyID: 101, source: rateLimitSourceFunc(func(context.Context, int64) (*dto.ThirdPartyAPIKeyListItem, error) {
			return nil, nil
		})},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := NewAPIKeyRateLimiter(test.source).Wait(context.Background(), test.keyID)
			if err == nil || (test.want != nil && !errors.Is(err, test.want)) {
				t.Fatalf("Wait() = %v, want error %v", err, test.want)
			}
		})
	}
	limiter := NewAPIKeyRateLimiter(fixedRateLimitSource(0))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := limiter.Wait(ctx, 101); !errors.Is(err, context.Canceled) {
		t.Fatalf("already-canceled request = %v", err)
	}
}
