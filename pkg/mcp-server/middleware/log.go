// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"encoding/hex"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/webhelp.v1/whmon"
	"gopkg.in/webhelp.v1/whroute"

	"storj.io/common/grant"
	"storj.io/common/http/requestid"
	"storj.io/common/process/gcloudlogging"
	"storj.io/edge/pkg/auth/authdb"
	"storj.io/edge/pkg/httplog"
	"storj.io/edge/pkg/trustedip"
)

// LogRequests logs requests.
func LogRequests(log *zap.Logger, h http.Handler) http.Handler {
	return whroute.HandlerFunc(h, func(w http.ResponseWriter, r *http.Request) {
		ce := log.Check(zap.DebugLevel, "access")
		if ce == nil {
			h.ServeHTTP(w, r)
			return
		}

		httpRequestLog := &gcloudlogging.HTTPRequest{
			Protocol:      r.Proto,
			RequestMethod: r.Method,
			RequestURL:    r.RequestURI,
			RequestSize:   r.ContentLength,
			UserAgent:     r.UserAgent(),
			RemoteIP:      getRemoteIP(r),
		}

		ce.Write([]zapcore.Field{
			gcloudlogging.LogHTTPRequest(httpRequestLog),
			zap.String("host", r.Host),
		}...)

		h.ServeHTTP(w, r)
	})
}

// LogResponses logs responses.
func LogResponses(log *zap.Logger, h http.Handler) http.Handler {
	return whmon.MonitorResponse(whroute.HandlerFunc(h,
		func(w http.ResponseWriter, r *http.Request) {
			rw := w.(whmon.ResponseWriter)
			start := time.Now()

			defer func() {
				rec := recover()
				if rec != nil {
					log.Error("panic", zap.Any("recover", rec))
					panic(rec)
				}
			}()
			h.ServeHTTP(rw, r)

			if !rw.WroteHeader() {
				rw.WriteHeader(http.StatusOK)
			}

			ce := log.Check(httplog.StatusLevel(rw.StatusCode()), "response")
			if ce == nil {
				return
			}

			httpRequestLog := &gcloudlogging.HTTPRequest{
				Protocol:      r.Proto,
				RequestMethod: r.Method,
				RequestURL:    r.RequestURI,
				RequestSize:   r.ContentLength,
				ResponseSize:  rw.Written(),
				Status:        rw.StatusCode(),
				UserAgent:     r.UserAgent(),
				RemoteIP:      getRemoteIP(r),
				Latency:       time.Since(start),
			}

			var macHead, encKeyHash, satelliteAddress, publicProjectID string
			credentials := GetCredentials(r.Context())
			if credentials != nil {
				if credentials.AccessGrant != "" {
					if access, err := grant.ParseAccess(credentials.AccessGrant); err == nil {
						macHead = hex.EncodeToString(access.APIKey.Head())
						satelliteAddress = access.SatelliteAddress
					}
				}
				if credentials.AccessKey != "" {
					var key authdb.EncryptionKey
					if err := key.FromBase32(credentials.AccessKey); err == nil {
						encKeyHash = key.Hash().ToHex()
					}
				}
				publicProjectID = credentials.PublicProjectID
			}

			ce.Write([]zapcore.Field{
				gcloudlogging.LogHTTPRequest(httpRequestLog),
				zap.String("host", r.Host),
				zap.String("request-id", requestid.FromContext(r.Context())),
				zap.String("public-project-id", publicProjectID),
				zap.String("encryption-key-hash", encKeyHash),
				zap.String("macaroon-head", macHead),
				zap.String("satellite-address", satelliteAddress),
			}...)
		}))
}

// NewLogRequests is a convenience wrapper around LogRequests that returns
// LogRequests as mux.MiddlewareFunc.
func NewLogRequests(log *zap.Logger) mux.MiddlewareFunc {
	return func(h http.Handler) http.Handler {
		return LogRequests(log, h)
	}
}

// NewLogResponses is a convenience wrapper around LogResponses that returns
// LogResponses as mux.MiddlewareFunc.
func NewLogResponses(log *zap.Logger) mux.MiddlewareFunc {
	return func(h http.Handler) http.Handler {
		return LogResponses(log, h)
	}
}

func getRemoteIP(r *http.Request) string {
	return trustedip.GetClientIP(trustedip.NewListTrustAll(), r)
}
