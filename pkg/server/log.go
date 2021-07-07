// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"net/http"
	"time"

	"go.uber.org/zap"
	"gopkg.in/webhelp.v1/whmon"
	"gopkg.in/webhelp.v1/whroute"

	"storj.io/gateway-mt/pkg/gwlog"
)

// LogRequestsNoPaths logs requests but without paths (which have sensitive info).
func LogRequestsNoPaths(log *zap.Logger, h http.Handler) http.Handler {
	return whroute.HandlerFunc(h, func(w http.ResponseWriter, r *http.Request) {
		log.Info("access", zap.String("method", r.Method),
			zap.String("host", r.Host),
			zap.String("user-agent", r.UserAgent()))
		h.ServeHTTP(w, r)
	})
}

// LogResponsesNoPaths logs requests and responsed but without paths (which have sensitive info).
func LogResponsesNoPaths(log *zap.Logger, h http.Handler) http.Handler {
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
				logGatewayResponse(log, r, rw, gl, time.Since(start))
				return
			}

			logResponse(log, r, rw, time.Since(start))
		}))
}

func logGatewayResponse(log *zap.Logger, r *http.Request, rw whmon.ResponseWriter, gl *gwlog.Log, d time.Duration) {
	level := log.Info
	if rw.StatusCode() >= 500 {
		level = log.Error
	}

	level("response", zap.String("method", r.Method),
		zap.String("host", r.Host),
		zap.Int("code", rw.StatusCode()),
		zap.String("user-agent", r.UserAgent()),
		zap.String("api", gl.API),
		zap.String("error", gl.TagValue("error")),
		zap.String("request-id", gl.RequestID),
		zap.String("access-key-sha256", gl.AccessKeyHash()),
		zap.Int64("content-length", r.ContentLength),
		zap.Int64("written", rw.Written()),
		zap.Duration("duration", d))
}

func logResponse(log *zap.Logger, r *http.Request, rw whmon.ResponseWriter, d time.Duration) {
	level := log.Info
	if rw.StatusCode() >= 500 {
		level = log.Error
	}

	level("response", zap.String("method", r.Method),
		zap.String("host", r.Host),
		zap.Int("code", rw.StatusCode()),
		zap.String("user-agent", r.UserAgent()),
		zap.Int64("content-length", r.ContentLength),
		zap.Int64("written", rw.Written()),
		zap.Duration("duration", d))
}
