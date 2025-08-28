// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"context"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/gorilla/mux"
	"github.com/spacemonkeygo/monkit/v3"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"storj.io/edge/pkg/authclient"
	"storj.io/edge/pkg/errdata"
)

var (
	mon = monkit.Package()

	accessRegexp = regexp.MustCompile("/access/.*\"")
)

type credentialsCV struct{}

// Credentials are user credentials set in context value.
type Credentials struct {
	AccessKey string
	authclient.AuthServiceResponse
}

// GetCredentials retrieves Credentials set in context value.
func GetCredentials(ctx context.Context) *Credentials {
	credentials, ok := ctx.Value(credentialsCV{}).(*Credentials)
	if !ok {
		return nil
	}
	return credentials
}

// CredentialsMiddleware is middleware for retrieving credentials and saving them to context value.
func CredentialsMiddleware(log *zap.Logger, authClient *authclient.AuthClient) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var err error
			ctx := r.Context()
			defer mon.TaskNamed("CredentialsMiddleware")(&ctx)(&err)

			accessKeyID := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if accessKeyID == "" {
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}

			authResp, err := authClient.ResolveWithCache(ctx, accessKeyID, "")
			if err != nil {
				logError(log, err)
				http.Error(w, authErrorMessage(err), errdata.GetStatus(err, http.StatusInternalServerError))
				return
			}

			if !slices.Contains(authResp.UsageTags, "mcp") {
				http.Error(w, "access key is missing required 'mcp' use-case tag", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, credentialsCV{}, &Credentials{
				AccessKey:           accessKeyID,
				AuthServiceResponse: authResp,
			})))
		})
	}
}

// authErrorMessage writes an appropriate error message to the user if it's related to the user
// providing an invalid access grant. Generic errors are shown for any status from authservice
// we don't recognise as it may contain internal information the user shouldn't see.
func authErrorMessage(err error) string {
	switch errdata.GetStatus(err, 0) {
	case http.StatusUnauthorized, http.StatusBadRequest:
		return "credentials error: " + err.Error()
	default:
		return "failed to resolve credentials"
	}
}

func logError(log *zap.Logger, err error) {
	// avoid logging access keys from errors, e.g.
	// "Get \"http://localhost:20000/v1/access/12345\": dial tcp ..."
	msg := accessRegexp.ReplaceAllString(err.Error(), "[...]\"")
	var level zapcore.Level

	switch errdata.GetStatus(err, http.StatusOK) {
	case http.StatusUnauthorized, http.StatusBadRequest:
		level = zap.DebugLevel
	case http.StatusInternalServerError:
		level = zap.ErrorLevel
	default:
		level = zap.ErrorLevel
	}

	ce := log.Check(level, "system")
	if ce != nil {
		ce.Write(zap.String("error", msg))
	}
}
