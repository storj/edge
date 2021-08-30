// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package backoff

import (
	"context"
	"time"
)

// ExponentialBackoff keeps track of how long we should sleep between
// failing attempts.
type ExponentialBackoff struct {
	delay time.Duration
	Max   time.Duration
	Min   time.Duration
}

func (e *ExponentialBackoff) init() {
	if e.Max == 0 {
		// maximum delay - pulled from net/http.Server.Serve
		e.Max = time.Second
	}
	if e.Min == 0 {
		// minimum delay - pulled from net/http.Server.Serve
		e.Min = 5 * time.Millisecond
	}
}

// Wait should be called when there is a failure. Each time it is called
// it will sleep an exponentially longer time, up to a max.
func (e *ExponentialBackoff) Wait(ctx context.Context) error {
	e.init()
	if e.delay == 0 {
		e.delay = e.Min
	} else {
		e.delay *= 2
	}
	if e.delay > e.Max {
		e.delay = e.Max
	}

	if ctx.Err() != nil {
		return ctx.Err()
	}

	t := time.NewTimer(e.delay)
	defer t.Stop()

	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Maxed returns true if the wait time has maxed out.
func (e *ExponentialBackoff) Maxed() bool {
	e.init()
	return e.delay == e.Max
}
