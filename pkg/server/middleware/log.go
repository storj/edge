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
	"storj.io/edge/pkg/server/gwlog"
	"storj.io/edge/pkg/trustedip"
)

// LogRequests logs requests.
func LogRequests(log *zap.Logger, h http.Handler, insecureLogPaths bool) http.Handler {
	return whroute.HandlerFunc(h, func(w http.ResponseWriter, r *http.Request) {
		httpRequestLog := &gcloudlogging.HTTPRequest{
			Protocol:      r.Proto,
			RequestMethod: r.Method,
			RequestSize:   r.ContentLength,
			UserAgent:     r.UserAgent(),
			RemoteIP:      getRemoteIP(r),
		}
		if insecureLogPaths {
			httpRequestLog.RequestURL = r.RequestURI
		}

		fields := []zapcore.Field{
			gcloudlogging.LogHTTPRequest(httpRequestLog),
			zap.String("host", r.Host),
		}

		log.Debug("access", fields...)
		h.ServeHTTP(w, r)
	})
}

// LogResponses logs responses.
func LogResponses(log *zap.Logger, h http.Handler, insecureLogAll bool) http.Handler {
	return whmon.MonitorResponse(whroute.HandlerFunc(h,
		func(w http.ResponseWriter, r *http.Request) {
			rw := w.(whmon.ResponseWriter)
			start := time.Now()

			ctx := r.Context()
			gl, ok := gwlog.FromContext(ctx)
			if !ok {
				gl = gwlog.New()
				r = r.WithContext(gl.WithContext(ctx))
			}

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

			if gl.RequestID != "" {
				logGatewayResponse(log, r, rw, gl, time.Since(start), insecureLogAll)
				return
			}

			logResponse(log, r, rw, time.Since(start), insecureLogAll)
		}))
}

// NewLogRequests is a convenience wrapper around LogRequests that returns
// LogRequests as mux.MiddlewareFunc.
func NewLogRequests(log *zap.Logger, insecureLogPaths bool) mux.MiddlewareFunc {
	return func(h http.Handler) http.Handler {
		return LogRequests(log, h, insecureLogPaths)
	}
}

// NewLogResponses is a convenience wrapper around LogResponses that returns
// LogResponses as mux.MiddlewareFunc.
func NewLogResponses(log *zap.Logger, insecureLogPaths bool) mux.MiddlewareFunc {
	return func(h http.Handler) http.Handler {
		return LogResponses(log, h, insecureLogPaths)
	}
}

func logGatewayResponse(log *zap.Logger, r *http.Request, rw whmon.ResponseWriter, gl *gwlog.Log, d time.Duration, insecureLogAll bool) {
	httpRequestLog := &gcloudlogging.HTTPRequest{
		Protocol:      r.Proto,
		RequestMethod: r.Method,
		RequestSize:   r.ContentLength,
		ResponseSize:  rw.Written(),
		Status:        rw.StatusCode(),
		UserAgent:     r.UserAgent(),
		RemoteIP:      getRemoteIP(r),
		Latency:       d,
	}
	if insecureLogAll {
		httpRequestLog.RequestURL = r.RequestURI
	}

	var accessKeyHash, macaroonHead, satelliteAddress string

	credentials := GetAccess(r.Context())
	if credentials != nil && credentials.AccessKey != "" {
		var key authdb.EncryptionKey
		if err := key.FromBase32(credentials.AccessKey); err == nil {
			accessKeyHash = key.Hash().ToHex()
		}
	}
	if credentials != nil && credentials.AccessGrant != "" {
		if access, err := grant.ParseAccess(credentials.AccessGrant); err == nil {
			macaroonHead = hex.EncodeToString(access.APIKey.Head())
			satelliteAddress = access.SatelliteAddress
		}
	}

	fields := []zapcore.Field{
		gcloudlogging.LogHTTPRequest(httpRequestLog),
		gcloudlogging.LogOperation(&gcloudlogging.Operation{
			ID:       gl.API,
			Producer: "storj.io/edge",
		}),
		zap.String("host", r.Host),
		zap.String("error", gl.TagValue("error")),
		zap.String("request-id", requestid.FromContext(r.Context())),
		zap.String("amz-request-id", gl.RequestID),
		zap.String("encryption-key-hash", accessKeyHash),
		zap.String("macaroon-head", macaroonHead),
		zap.String("satellite-address", satelliteAddress),
		zap.String("trace-id", rw.Header().Get("trace-id")),
		zap.Object("query", &httplog.RequestQueryLogObject{
			Query:                                   r.URL.Query(),
			InsecureDisableConfidentialSanitization: insecureLogAll,
		}),
		zap.Object("request-headers", &httplog.HeadersLogObject{
			Headers:                                 r.Header,
			InsecureDisableConfidentialSanitization: insecureLogAll,
		}),
		zap.Object("response-headers", &httplog.HeadersLogObject{
			Headers:                                 rw.Header(),
			InsecureDisableConfidentialSanitization: true, // we don't need to hide any known response header values.
		}),
	}

	if ce := log.Check(httplog.StatusLevel(rw.StatusCode()), "response"); ce != nil {
		ce.Write(fields...)
	}
}

func getRemoteIP(r *http.Request) string {
	return trustedip.GetClientIP(trustedip.NewListTrustAll(), r)
}

func logResponse(log *zap.Logger, r *http.Request, rw whmon.ResponseWriter, d time.Duration, insecureLogAll bool) {
	httpRequestLog := &gcloudlogging.HTTPRequest{
		Protocol:      r.Proto,
		RequestMethod: r.Method,
		RequestSize:   r.ContentLength,
		ResponseSize:  rw.Written(),
		Status:        rw.StatusCode(),
		UserAgent:     r.UserAgent(),
		RemoteIP:      getRemoteIP(r),
		Latency:       d,
	}
	if insecureLogAll {
		httpRequestLog.RequestURL = r.RequestURI
	}

	fields := []zapcore.Field{
		gcloudlogging.LogHTTPRequest(httpRequestLog),
		zap.String("host", r.Host),
	}

	if ce := log.Check(httplog.StatusLevel(rw.StatusCode()), "response"); ce != nil {
		ce.Write(fields...)
	}
}
