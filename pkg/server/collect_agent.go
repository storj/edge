// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"net/http"

	"gopkg.in/webhelp.v1/whroute"

	"storj.io/common/eventstat"
	"storj.io/common/useragent"
)

// AgentCollector is a helper to register monkit monitor for HTTP User-Agents.
type AgentCollector struct {
	counter eventstat.Sink
}

// NewAgentCollector creates a new collector and registers it to a monkit scope.
func NewAgentCollector(name string, counter eventstat.Sink) *AgentCollector {
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
		a.counter(product)
		h.ServeHTTP(w, r)
	})
}
