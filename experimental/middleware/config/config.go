// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package config

import (
	"context"
	"net/http"

	"github.com/storj/gateway-mt/experimental/pkg/authc"
	"storj.io/common/rpc/rpcpool"
	"storj.io/uplink"
)

type contextKey struct{}

// Config stores service configuration.
type Config struct {
	Domain       string
	UplinkConfig *uplink.Config
	RPCPool      *rpcpool.Pool
	AuthClient   *authc.Client
}

// Middleware implements mux.Middlware.
func (c *Config) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey{}, c)))
	})
}

// GetConfig returns the config.
func GetConfig(ctx context.Context) *Config {
	return ctx.Value(contextKey{}).(*Config)
}
