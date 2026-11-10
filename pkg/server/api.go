// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/amwolff/awsig"
	"github.com/gorilla/mux"
	"go.uber.org/zap"

	"storj.io/edge/pkg/errdata"
	"storj.io/edge/pkg/minio"
	"storj.io/edge/pkg/server/gw"
	"storj.io/edge/pkg/server/middleware"
	"storj.io/gateway/api"
	"storj.io/gateway/api/apierr"
)

const defaultSlowDownRetryAfter = 12 * time.Second

// limitedOperations are the operations whose concurrency is limited per credential.
var limitedOperations = []string{"GetObject", "PutObject", "UploadPart", "PostObject"}

// registerAPI registers the handlers of gateway's api package on r, instead of minio's.
func registerAPI(log *zap.Logger, r *mux.Router, layer *gw.MultiTenancyLayer, domains, corsAllowedOrigins []string, concurrentAllowed uint) error {
	retryAfter, err := slowDownRetryAfter()
	if err != nil {
		return err
	}

	var s3API *api.API

	limiter := middleware.NewConcurrentRequestsLimiter(concurrentAllowed, func(w http.ResponseWriter, r *http.Request) {
		s3API.WriteErrorResponse(w, r, apierr.Response{
			Code:           "SlowDown",
			Description:    fmt.Sprintf("Only %d concurrent uploads or downloads are allowed per credential", concurrentAllowed),
			HTTPStatusCode: http.StatusTooManyRequests,
		})
	})
	limit := func(next http.Handler) http.Handler {
		limited := limiter.Limit(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if slices.Contains(limitedOperations, api.Operation(r)) {
				limited.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}

	s3API = api.New(layer, credentialsProvider{}, api.Config{
		Domains: domains,
		CORS: &api.CORSConfiguration{Rules: []api.CORSRule{{
			AllowedHeaders: []string{"*"},
			AllowedMethods: minio.CorsAllowedMethods,
			AllowedOrigins: corsAllowedOrigins,
			ExposeHeaders:  []string{"*"},
		}}},
		SlowDownRetryAfter: retryAfter,
	}, api.WithLogger(api.NewZapLogger(log)), api.WithMiddleware(limit))

	s3API.RegisterHandlers(r)
	return nil
}

// slowDownRetryAfter returns the seconds in STORJ_MINIO_RETRY_AFTER, which minio's handlers also
// read, or defaultSlowDownRetryAfter if it isn't set.
func slowDownRetryAfter() (time.Duration, error) {
	value, ok := os.LookupEnv("STORJ_MINIO_RETRY_AFTER")
	if !ok {
		return defaultSlowDownRetryAfter, nil
	}
	seconds, err := strconv.Atoi(value)
	if err != nil {
		return 0, Error.New("STORJ_MINIO_RETRY_AFTER must be whole seconds, not %q", value)
	}
	return time.Duration(seconds) * time.Second, nil
}

// credentialsProvider provides the secret key that middleware.AccessKey resolved for the request.
type credentialsProvider struct{}

// Provide implements awsig.CredentialsProvider.
func (credentialsProvider) Provide(ctx context.Context, accessKeyID string) (string, api.AuthData, error) {
	credentials := middleware.GetAccess(ctx)
	if credentials == nil {
		return "", api.AuthData{}, awsig.ErrInvalidAccessKeyID
	}
	// Failed lookups leave AccessKey empty, so they're checked before it's compared.
	if credentials.Error != nil {
		// authclient answers 400 for a malformed access key and authservice 401 for an unknown one.
		switch errdata.GetStatus(credentials.Error, http.StatusOK) {
		case http.StatusBadRequest, http.StatusUnauthorized:
			return "", api.AuthData{}, awsig.ErrInvalidAccessKeyID
		}
		return "", api.AuthData{}, credentials.Error
	}
	if credentials.AccessKey != accessKeyID {
		return "", api.AuthData{}, awsig.ErrInvalidAccessKeyID
	}
	return credentials.SecretKey, api.AuthData{AccessKeyID: accessKeyID}, nil
}
