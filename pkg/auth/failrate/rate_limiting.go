// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package failrate

import (
	"net/http"
	"sync"
	"time"

	"github.com/zeebo/errs"
	"golang.org/x/time/rate"

	"storj.io/common/lrucache"
	"storj.io/gateway-mt/pkg/trustedip"
)

// LimitersConfig configures a failure rate limiter.
type LimitersConfig struct {
	MaxReqsSecond int `help:"maximum number of allowed operations per second starting when first failure operation happens" default:"2" testDefault:"1"`
	Burst         int `help:"maximum number of allowed operations to overpass the maximum operations per second" default:"3" testDefault:"1"`
	NumLimits     int `help:"maximum number of keys/rate-limit pairs stored in the LRU cache" default:"1000" testDefault:"10"`
}

// Limiters register a rate limit per key when the operation is marked as failed
// for allowing to track subsequent operations on the registered keys and count
// the failed operations to be limited.
//
// The successful ones do not count to the rate limit nor contribute to
// unregister them.
type Limiters struct {
	limiters *lrucache.ExpiringLRU
	limit    rate.Limit
	burst    int
}

// NewLimiters creates an Limiters returning an error if the c.MaxReqSecond,
// c.Burst or c.NumLimits are 0 or negative.
func NewLimiters(c LimitersConfig) (*Limiters, error) {
	if c.MaxReqsSecond <= 0 {
		return nil, errs.New("MaxReqsSecond cannot be zero or negative")
	}

	if c.Burst <= 0 {
		return nil, errs.New("Burst cannot be zero or negative")
	}

	if c.NumLimits <= 0 {
		return nil, errs.New("NumLimits cannot be zero or negative")
	}

	return &Limiters{
		limiters: lrucache.New(lrucache.Options{Capacity: c.NumLimits}),
		limit:    1 / rate.Limit(c.MaxReqsSecond), // minium interval between requests
		burst:    c.Burst,
	}, nil
}

// Allow returns true and non-nil succeeded and failed, and a zero delay if key
// is allowed to perform an operation, otherwise false, succeeded and failed are
// nil, and delay is greater than 0.
//
// key is allowed to make the request if it isn't tracked or it's tracked but it
// hasn't reached the limit.
//
// When key isn't tracked, it gets tracked when failed is executed and
// subsequent Allow calls with key will be rate-limited. succeeded untrack the
// key when the rate-limit doesn't apply anymore. For these reason the caller
// MUST always call succeeded or failed when true is returned.
func (irl *Limiters) Allow(key string) (allowed bool, succeeded func(), failed func(), delay time.Duration) {
	v, ok := irl.limiters.GetCached(key)
	if ok {
		rl := v.(*limiter)
		allowed, delay, rollback := rl.Allow()
		if !allowed {
			return false, nil, nil, delay
		}

		// When the key is already tracked, failed func doesn't have to do anything.
		return true, func() {
			// The operations has succeeded, hence rollback the consumed rate-limit
			// allowance.
			rollback()

			if rl.IsOnInitState() {
				irl.limiters.Delete(key)
			}
		}, func() {}, 0
	}

	return true, func() {}, func() {
		// The operation is failed, hence we start to rate-limit the key.
		rl := newRateLimiter(irl.limit, irl.burst)
		irl.limiters.Add(key, rl)
		// Consume one operation, which is this failed one.
		rl.Allow()
	}, 0
}

// limitersAllowReqTrustAnyIP avoids to call thist method on every
// Limiters.AllowReq call.
var limitersAllowReqTrustAnyIP = trustedip.NewListTrustAll()

// AllowReq gets uses the client IP from r as key to call the Allow method.
//
// It gets the IP of the client from the 'Forwarded', 'X-Forwarded-For', or
// 'X-Real-Ip' headers, returning it from the first header which are checked in
// that specific order; if any of those header exists then it gets the IP from
// r.RemoteAddr.
// It panics if r is nil.
func (irl *Limiters) AllowReq(r *http.Request) (allowed bool, succeeded func(), failed func(), delay time.Duration) {
	ip := trustedip.GetClientIP(limitersAllowReqTrustAnyIP, r)
	return irl.Allow(ip)
}

// limiter is a wrapper around rate.Limiter to suit the Limiters reui
// requirements.
type limiter struct {
	limiter *rate.Limiter

	mu          sync.Mutex
	reservation *reservation
}

func newRateLimiter(limit rate.Limit, burst int) *limiter {
	return &limiter{
		limiter: rate.NewLimiter(limit, burst),
	}
}

// IsOnInitState returns true if the rate-limiter is back to its full allowance
// such is when it is created.
func (rl *limiter) IsOnInitState() bool {
	now := time.Now()
	rsvt := rl.limiter.ReserveN(now, rl.limiter.Burst())
	// Cancel immediately the reservation because we are only interested in the
	// finding out the delay of executing as many operations as burst.
	// 	Using the same time when the reservation was created allows to cancel
	// the reservation despite it's already consumed at this moment.
	rsvt.CancelAt(now)

	return rsvt.Delay() == 0
}

// Allow returns true when the operations is allowed to be performed, and also
// returns a rollback function for rolling it back the consumed token for not
// counting to the rate-limiting of future calls. Otherwise it returns false
// and the time duration that the caller must wait until being allowed to
// perform the operation and rollback is nil because there isn't an allowed
// operations to roll it back.
func (rl *limiter) Allow() (_ bool, _ time.Duration, rollback func()) {
	now := time.Now()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	rsvt := rl.reservation
	if rsvt == nil {
		rsvt = newReservation(rl.limiter, now)
	}

	if d := rsvt.Delay(now); d > 0 {
		// If there is an imposed delay, it means that the reserved token cannot
		// be consumed right now, so isn't allowed.
		rl.reservation = rsvt
		return false, d, nil
	}

	// The reservation can be consumed now, so we don't need to hold it anymore.
	rl.reservation = nil

	return true, 0, func() {
		// 	Cancel the reservation if this allowance rolled back.
		rsvt.Cancel()
	}
}

// reservation is a wrapper of rate.Reservation for holding the time that is
// created and being able to cancel it in the future but retrospectively to its
// creation time.
type reservation struct {
	r         *rate.Reservation
	createdAt time.Time
}

func newReservation(limiter *rate.Limiter, now time.Time) *reservation {
	return &reservation{
		r:         limiter.ReserveN(now, 1),
		createdAt: now,
	}
}

// Delay returns the time that the caller should way to consumed it.
//
// Basically it's a wrapper of calling the rate.Reservation.DelayFrom, check its
// documentation for further information.
func (rsvp *reservation) Delay(now time.Time) time.Duration {
	return rsvp.r.DelayFrom(now)
}

// Cancel cancels the reservation retrospectively to its creation time.
//
// Basically it's a wrapper of calling the rate.Reservation.CanceltAt passing
// its creation time; check its documentation for further information.
func (rsvp *reservation) Cancel() {
	rsvp.r.CancelAt(rsvp.createdAt)
}
