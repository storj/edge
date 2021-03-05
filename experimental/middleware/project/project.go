// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package project

import (
	"context"
	"net/http"

	"github.com/storj/gateway-mt/experimental/middleware/config"
	"github.com/storj/minio/pkg/storj/middleware/signature"
	"github.com/storj/minio/pkg/storj/model"
	"storj.io/uplink"
	"storj.io/uplink/private/transport"
)

type contextKey struct{}

// Project data
type Project struct{}

// New returns a new project middleware.
func New() *Project {
	return &Project{}
}

// Middleware implements mux.Middlware.
func (p *Project) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		creds := signature.GetCredentials(ctx)

		serverConfig := config.GetConfig(ctx)

		authAccess, err := serverConfig.AuthClient.GetAccess(ctx, creds.AccessKeyID)
		if err != nil {
			model.Error{
				Err:    err,
				Status: 403,
			}.ServeHTTP(w, r)

			return
		}

		accessGrant, err := uplink.ParseAccess(authAccess.AccessGrant)
		if err != nil {
			model.Error{
				Err:    err,
				Status: 500,
			}.ServeHTTP(w, r)

			return
		}

		uplinkConfig := serverConfig.UplinkConfig
		uplinkConfig.UserAgent = r.UserAgent() + " gateway-mt/0.0.0"

		err = transport.SetConnectionPool(ctx, serverConfig.UplinkConfig, serverConfig.RPCPool)
		if err != nil {
			model.Error{
				Err:    err,
				Status: 500,
			}.ServeHTTP(w, r)

			return
		}

		uplinkProject, err := uplinkConfig.OpenProject(ctx, accessGrant)
		if err != nil {
			model.Error{
				Err:    err,
				Status: 500,
			}.ServeHTTP(w, r)

			return
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, contextKey{}, uplinkProject)))
	})
}

// GetUplinkProject returns the uplink project.
func GetUplinkProject(ctx context.Context) *uplink.Project {
	return ctx.Value(contextKey{}).(*uplink.Project)
}
