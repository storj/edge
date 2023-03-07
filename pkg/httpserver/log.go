// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package httpserver

import (
	"net/http"
	"time"

	"go.uber.org/zap"
	"gopkg.in/webhelp.v1/whmon"
	"gopkg.in/webhelp.v1/whroute"

	"storj.io/gateway-mt/pkg/httplog"
	"storj.io/gateway-mt/pkg/middleware"
	"storj.io/gateway-mt/pkg/trustedip"
	"storj.io/private/process/gcloudlogging"
)

func logRequests(log *zap.Logger, h http.Handler) http.Handler {
	return whroute.HandlerFunc(h, func(w http.ResponseWriter, r *http.Request) {
		log.Debug("access",
			gcloudlogging.LogHTTPRequest(&gcloudlogging.HTTPRequest{
				Protocol:      r.Proto,
				RequestMethod: r.Method,
				RequestSize:   r.ContentLength,
				UserAgent:     r.UserAgent(),
				RemoteIP:      trustedip.GetClientIP(trustedip.NewListTrustAll(), r),
			}),
			zap.String("host", r.Host),
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

			if ce := log.Check(httplog.StatusLevel(rw.StatusCode()), "response"); ce != nil {
				ce.Write(gcloudlogging.LogHTTPRequest(&gcloudlogging.HTTPRequest{
					Protocol:      r.Proto,
					RequestMethod: method,
					RequestSize:   r.ContentLength,
					ResponseSize:  rw.Written(),
					UserAgent:     r.UserAgent(),
					RemoteIP:      remoteIP(r),
					Latency:       time.Since(start),
					Status:        rw.StatusCode(),
				}),
					zap.String("host", host),
					zap.String("request-id", middleware.GetRequestID(r.Context())),
					// we are deliberately not logging the request URI as it has
					// sensitive information in it.
				)
			}
		}))
}

func remoteIP(r *http.Request) string {
	return trustedip.GetClientIP(trustedip.NewListTrustAll(), r)
}
