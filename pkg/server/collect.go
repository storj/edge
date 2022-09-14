// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"encoding/hex"
	"net/http"

	"gopkg.in/webhelp.v1/whroute"

	"storj.io/common/eventstat"
	"storj.io/common/grant"
	"storj.io/common/useragent"
	"storj.io/gateway-mt/pkg/server/middleware"
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

// MacaroonHeadCollector is a helper to register monkit monitor for macaroon heads.
type MacaroonHeadCollector struct {
	counter eventstat.Sink
}

// NewMacaroonHeadCollector creates a new collector and registers it to a monkit scope.
func NewMacaroonHeadCollector(name string, counter eventstat.Sink) *MacaroonHeadCollector {
	return &MacaroonHeadCollector{
		counter: counter,
	}
}

// Wrap creates statistics about used macaroon heads.
func (m *MacaroonHeadCollector) Wrap(h http.Handler) http.Handler {
	return whroute.HandlerFunc(h, func(w http.ResponseWriter, r *http.Request) {
		credentials := middleware.GetAccess(r.Context())
		if credentials == nil || credentials.AccessGrant == "" {
			h.ServeHTTP(w, r)
			return
		}
		access, err := grant.ParseAccess(credentials.AccessGrant)
		if err != nil {
			h.ServeHTTP(w, r)
			return
		}
		m.counter(hex.EncodeToString(access.APIKey.Head()))
		h.ServeHTTP(w, r)
	})
}
