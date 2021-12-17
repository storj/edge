// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package failrate

import (
	"fmt"
	"math/rand"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"

	"storj.io/common/lrucache"
	"storj.io/common/testcontext"
)

func TestLimiters(t *testing.T) {
	const ip = "172.28.254.80"

	ctx := testcontext.New(t)
	req := &http.Request{
		RemoteAddr: "10.5.2.23",
		Header: map[string][]string{
			"X-Forwarded-For": {fmt.Sprintf("%s, 192.168.80.25", ip)},
			"Forwarded":       {fmt.Sprintf("for=%s, for=172.17.5.10", ip)},
			"X-Real-Ip":       {ip},
		},
	}
	req = req.WithContext(ctx)

	limiters, err := NewLimiters(LimitersConfig{MaxReqsSecond: 2, Burst: 3, NumLimits: 1})
	require.NoError(t, err)

	{ // Succeesful requests doesn't count to rate limit the IP.
		for i := 1; i <= 10; i++ {
			allowed, succeeded, _, _ := limiters.AllowReq(req)
			require.Truef(t, allowed, "AlloReq: request %d", i)
			succeeded()
		}

		for i := 1; i <= 10; i++ {
			allowed, succeeded, _, _ := limiters.Allow(ctx, ip)
			require.Truef(t, allowed, "Allow: request %d", i)
			succeeded()
		}

		assertLRUContains(t, limiters.limiters, ip, false, "IP with successful requests doesn't have assigned a rate limiter")
	}

	{ // Failed requests counts to rate limit the IP.
		for i := 1; i <= 2; i++ {
			allowed, _, failed, _ := limiters.AllowReq(req)
			require.Truef(t, allowed, "AllowReq: request %d", i)
			failed()
		}

		// Execute the last one allowed but using directly the key (i.e. IP).
		allowed, _, failed, _ := limiters.Allow(ctx, ip)
		require.True(t, allowed, "Allow: request 3")
		failed()

		baseDelay := 2 * time.Second
		for i := 4; i <= 5; i++ {
			allowed, _, _, delay := limiters.AllowReq(req)
			assert.Falsef(t, allowed, "AllowReq: request %d", i)
			assert.LessOrEqual(t, delay, baseDelay, "retry duration")

			baseDelay += time.Second / 2
		}

		// Execute another one not allowed but using directly the key (i.e. IP).
		allowed, _, _, _ = limiters.Allow(ctx, ip)
		assert.False(t, allowed, "Allow: request 6")
	}

	{ // New key evicts the oldest one when the cache size is reached.
		const key = "new-key-evicts-older-one"
		allowed, _, failed, _ := limiters.Allow(ctx, key)
		require.True(t, allowed, "Allow")
		failed()
		assertLRUContains(t, limiters.limiters, ip, false, "previous key should have been removed")
	}

	{ // Succeeded removes an existing rate limit when it reaches the initial state.
		const key = "will-be-at-init-state"
		assertLRUContains(t, limiters.limiters, ip, false, "new key should be in the cache")

		allowed, _, failed, _ := limiters.Allow(ctx, key)
		require.True(t, allowed, "Allow")
		// Failed operation counts for being rate-limited.
		failed()
		rateLimitStarted := time.Now() // this is because of the previous failed call.

		assertLRUContains(t, limiters.limiters, key, true, "failed key should be in the cache")

		allowed, succeeded, _, _ := limiters.Allow(ctx, key)
		require.True(t, allowed, "Allow")
		assertLRUContains(t, limiters.limiters, key, true, "allow shouldn't remove the key from the cache")
		succeeded()

		// Wait the time until the rate-limiter associated with the key is back to
		// it's initial state. That's the time that can reserve an amount of
		// operations equal to the burst without any delay.
		time.Sleep(time.Until(rateLimitStarted.Add(2 * time.Second)))
		allowed, succeeded, _, _ = limiters.Allow(ctx, key)
		require.True(t, allowed, "Allow")
		// Succeeded remove a tracked rate-limiter when it's to it's initial state.
		succeeded()
		// Verify that the rate-limiter has been untracked.
		assertLRUContains(t, limiters.limiters, key, false, "succeeded should remove the key from the cache")
	}

	{ // Cheaters cannot use successful operations to bypass it.
		const key = "cheater"

		for i := 1; i <= 2; i++ {
			allowed, _, failed, _ := limiters.Allow(ctx, key)
			require.True(t, allowed, "Allow")
			// Failed operation counts for being rate-limited.
			failed()
		}

		// This operation is still allowed because of the burst allowance.
		allowed, succeeded, _, _ := limiters.Allow(ctx, key)
		require.True(t, allowed, "Allow")
		// Succeeded operation doesn't count for being rate-limited
		succeeded()
		assertLRUContains(t, limiters.limiters, key, true,
			"one succeeded operation shouldn't remove the key from the cache when there is not delay",
		)

		// This operation is still allowed because of the burst allowance and because
		// the previous one succeeded, so it wasn't count by the rate-limited.
		allowed, _, failed, _ := limiters.Allow(ctx, key)
		require.True(t, allowed, "Allow")
		failed()

		// This operation is rate limited because the rate limit has not been
		// cleared due to the last succeeded operations and it has surpassed the
		// burst allowance.
		allowed, _, _, _ = limiters.Allow(ctx, key)
		assert.False(t, allowed, "Allow")
	}

	t.Run("not allowed key is allowed again if it waits for the delay for the following request", func(t *testing.T) {
		const key = "no-allowed-wait-allowed-again"

		limiters, err := NewLimiters(LimitersConfig{MaxReqsSecond: 1, Burst: 1, NumLimits: 1})
		require.NoError(t, err)

		// Explicitly reduce the time between calls to limit less than the minium
		// the configuration allows for speeding the test up.
		limiters.limit = rate.Every(time.Millisecond)

		allowed, _, failed, _ := limiters.Allow(ctx, key)
		require.True(t, allowed, "Allow: call 1")
		failed()

		allowed, _, _, delay := limiters.Allow(ctx, key)
		// NOTE: it would fail if this second call to Allow isn't executed at least
		// one millisecond than the previous one, hence this test will be flaky and
		// we should use a greater duration for the limiters.limit at the expense of
		// increasing the test running time.
		assert.False(t, allowed, "Allow: call 2")
		assert.LessOrEqual(t, delay, time.Millisecond, "retry duration")

		time.Sleep(time.Millisecond)
		allowed, succeeded, _, _ := limiters.Allow(ctx, key)
		require.True(t, allowed, "Allow: call after wait")
		succeeded()
	})
}

func TestNewLimiters(t *testing.T) {
	limiters, err := NewLimiters(LimitersConfig{
		MaxReqsSecond: 5, Burst: 1, NumLimits: 1,
	})
	require.NoError(t, err)
	require.NotNil(t, limiters)
}

func TestNewLimiters_error(t *testing.T) {
	testCases := []struct {
		desc   string
		config LimitersConfig
	}{
		{
			desc:   "zero max reqs per second",
			config: LimitersConfig{MaxReqsSecond: 0, Burst: 2, NumLimits: 1},
		},
		{
			desc:   "negative max reqs per second",
			config: LimitersConfig{MaxReqsSecond: -1, Burst: 5, NumLimits: 1},
		},
		{
			desc:   "zero burst",
			config: LimitersConfig{MaxReqsSecond: 9, Burst: 0, NumLimits: 1},
		},
		{
			desc:   "negative burst",
			config: LimitersConfig{MaxReqsSecond: 15, Burst: -5, NumLimits: 1},
		},
		{
			desc:   "zero num limits",
			config: LimitersConfig{MaxReqsSecond: 5, Burst: 3, NumLimits: 0},
		},
		{
			desc:   "negative num limits",
			config: LimitersConfig{MaxReqsSecond: 5, Burst: 1, NumLimits: -3},
		},
		{
			desc:   "negative max reqs per second and num limits",
			config: LimitersConfig{MaxReqsSecond: -2, Burst: 10, NumLimits: -1},
		},
		{
			desc:   "zero burst and negative num limits",
			config: LimitersConfig{MaxReqsSecond: 3, Burst: -1, NumLimits: -1},
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			_, err := NewLimiters(tC.config)
			require.Error(t, err)
		})
	}
}

func TestLimiters_concurrency(t *testing.T) {
	limiters, err := NewLimiters(LimitersConfig{MaxReqsSecond: 2, Burst: 1, NumLimits: 2})
	require.NoError(t, err)

	// Explicitly reduce the time between calls to limit less than the minium
	// the configuration allows for speeding the test up.
	limiters.limit = rate.Every(time.Millisecond)

	const iterations = 50
	ctx := testcontext.New(t)

	// Target key1
	ctx.Go(func() error {
		for i := 0; i < iterations; i++ {
			allow, succeeded, failed, delay := limiters.Allow(ctx, "key1")
			if !allow {
				time.Sleep(delay)
			} else {
				if rand.Int()%2 == 0 {
					failed()
				} else {
					succeeded()
				}
			}
		}

		return nil
	})

	// Target key1
	ctx.Go(func() error {
		for i := 0; i < iterations; i++ {
			allow, succeeded, failed, delay := limiters.Allow(ctx, "key1")
			if !allow {
				time.Sleep(delay)
			} else {
				if rand.Int()%2 == 0 {
					failed()
				} else {
					succeeded()
				}
			}
		}

		return nil
	})

	// Target key2
	ctx.Go(func() error {
		for i := 0; i < iterations; i++ {
			allow, succeeded, failed, delay := limiters.Allow(ctx, "key2")
			if !allow {
				time.Sleep(delay)
			} else {
				if rand.Int()%2 == 0 {
					failed()
				} else {
					succeeded()
				}
			}
		}

		return nil
	})

	// Target key2
	ctx.Go(func() error {
		for i := 0; i < iterations; i++ {
			allow, succeeded, failed, delay := limiters.Allow(ctx, "key2")
			if !allow {
				time.Sleep(delay)
			} else {
				if rand.Int()%2 == 0 {
					failed()
				} else {
					succeeded()
				}
			}
		}

		return nil
	})

	ctx.Wait()
}

func assertLRUContains(t *testing.T, lru *lrucache.ExpiringLRU, key string, contains bool, msg string) {
	t.Helper()

	_, cached := lru.GetCached(key)
	assert.Equal(t, contains, cached, msg)
}
