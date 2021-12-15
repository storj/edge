// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package backoff

import (
	"context"
	"time"

	"github.com/spacemonkeygo/monkit/v3"
)

var mon = monkit.Package()

// ExponentialBackoff provides delays between failing attempts.
type ExponentialBackoff struct {
	Delay time.Duration `help:"The active time between retries, typically not set" default:"0ms"`
	Max   time.Duration `help:"The maximum total time to allow retries" default:"5m"`
	Min   time.Duration `help:"The minimum time between retries" default:"100ms"`
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
func (e *ExponentialBackoff) Wait(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	e.init()
	if e.Delay == 0 {
		e.Delay = e.Min
	} else {
		e.Delay *= 2
	}
	if e.Delay > e.Max {
		e.Delay = e.Max
	}

	if ctx.Err() != nil {
		return ctx.Err()
	}

	t := time.NewTimer(e.Delay)
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
	return e.Delay == e.Max
}
