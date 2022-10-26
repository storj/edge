// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package httpserver

import (
	"net/http"
	"time"

	"go.uber.org/zap"
	"gopkg.in/webhelp.v1/whmon"
	"gopkg.in/webhelp.v1/whroute"

	"storj.io/gateway-mt/pkg/middleware"
	"storj.io/gateway-mt/pkg/trustedip"
)

func logRequests(log *zap.Logger, h http.Handler) http.Handler {
	return whroute.HandlerFunc(h, func(w http.ResponseWriter, r *http.Request) {
		log.Info("access",
			zap.String("method", r.Method),
			zap.String("host", r.Host),
			zap.String("user-agent", r.UserAgent()),
			zap.String("remote-ip", remoteIP(r)),
			// we are deliberately not logging the request URI as it has
			// sensitive information in it.
		)
		h.ServeHTTP(w, r)
	})
}

func logResponses(log *zap.Logger, h http.Handler) http.Handler {
	return whmon.MonitorResponse(whroute.HandlerFunc(h,
		func(w http.ResponseWriter, r *http.Request) {
			method, host := r.Method, r.Host
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

			code := rw.StatusCode()

			level := log.Info
			if code >= 500 {
				level = log.Error
			}
			level("response",
				zap.String("method", method),
				zap.String("host", host),
				// we are deliberately not logging the request URI as it has
				// sensitive information in it.
				zap.Int("code", code),
				zap.String("request-id", middleware.GetRequestID(r.Context())),
				zap.String("user-agent", r.UserAgent()),
				zap.String("remote-ip", remoteIP(r)),
				zap.Int64("content-length", r.ContentLength),
				zap.Int64("written", rw.Written()),
				zap.Duration("duration", time.Since(start)))
		}))
}

func remoteIP(r *http.Request) string {
	return trustedip.GetClientIP(trustedip.NewListTrustAll(), r)
}
