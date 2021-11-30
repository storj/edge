// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"net/http"
	"sync"

	"github.com/spacemonkeygo/monkit/v3"
	"gopkg.in/webhelp.v1/whroute"

	"storj.io/common/useragent"
)

// AgentCollector is a helper to register monkit monitor for HTTP User-Agents.
type AgentCollector struct {
	counter *TagCounter
}

// NewAgentCollector creates a new collector and registers it to a monkit scope.
func NewAgentCollector(name string, scope *monkit.Scope) *AgentCollector {
	counter := NewTagCounter(name)
	scope.Chain(counter)
	return &AgentCollector{
		counter: counter,
	}
}

// Wrap creates statistics about used HTTP user agent (string part).
func (a *AgentCollector) Wrap(h http.Handler) http.Handler {
	return whroute.HandlerFunc(h, func(w http.ResponseWriter, r *http.Request) {
		agents, err := useragent.ParseEntries([]byte(r.UserAgent()))
		product := "unknown"
		if err == nil && len(agents) > 0 && agents[0].Product != "" {
			product = agents[0].Product
			if len(product) > 32 {
				product = product[:32]
			}
		}
		a.counter.Increment(product)
		h.ServeHTTP(w, r)
	})
}

// TagCounter is counting tags since last stat/report.
// use it for datasets with high cardinality to keep memory usage on low.
type TagCounter struct {
	mu       sync.Mutex
	counters map[string]uint64
	name     string
}

// NewTagCounter creates a new TagCounter with name user for the reported metrics.
func NewTagCounter(measurement string) *TagCounter {
	return &TagCounter{
		counters: map[string]uint64{},
		name:     measurement,
	}
}

// Stats implements the monkit.StatSource interface.
func (c *TagCounter) Stats(cb func(key monkit.SeriesKey, field string, val float64)) {
	c.mu.Lock()
	counters := c.counters
	for key := range c.counters {
		delete(c.counters, key)
	}
	c.mu.Unlock()

	for name, value := range counters {
		key := monkit.NewSeriesKey(c.name).WithTags(monkit.NewSeriesTag("agent", name))
		cb(key, "count", float64(value))
	}
	cb(monkit.NewSeriesKey(c.name), "samples", float64(len(counters)))
}

// Increment bumps the usage count of one of the counters.
func (c *TagCounter) Increment(tag string) {
	c.mu.Lock()
	// safety valve, hard limit the memory / network usage
	if len(c.counters) < 1000 {
		c.counters[tag]++
	} else {
		// no new counters, but bump the value
		_, found := c.counters[tag]
		if found {
			c.counters[tag]++
		} else {
			c.counters["<DISCARDED>"]++
		}
	}
	c.mu.Unlock()
}
