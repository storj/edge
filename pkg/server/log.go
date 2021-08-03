// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	xhttp "github.com/storj/minio/cmd/http"
	"go.uber.org/zap"
	"gopkg.in/webhelp.v1/whmon"
	"gopkg.in/webhelp.v1/whroute"

	"storj.io/gateway-mt/pkg/server/gwlog"
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

	var query []string
	for k, v := range r.URL.Query() {
		var val string
		// obfuscate any credentials in the query value.
		// https://docs.aws.amazon.com/general/latest/gr/signature-version-2.html
		// https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
		switch k {
		case xhttp.AmzAccessKeyID, xhttp.AmzSignatureV2, xhttp.AmzSignature, xhttp.AmzCredential:
			val = "[...]"
		default:
			val = strings.Join(v, ",")
		}
		query = append(query, fmt.Sprintf("%s=%s", k, val))
	}

	var reqHeaders []string
	for k, v := range r.Header {
		var val string
		// obfuscate any credentials in headers.
		switch k {
		case xhttp.Authorization, "Cookie":
			val = "[...]"
		default:
			val = strings.Join(v, ",")
		}
		reqHeaders = append(reqHeaders, fmt.Sprintf("%s=%s", k, val))
	}

	var rspHeaders []string
	for k, v := range rw.Header() {
		rspHeaders = append(rspHeaders, fmt.Sprintf("%s=%s", k, strings.Join(v, ",")))
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
		zap.Duration("duration", d),
		zap.Strings("query", query),
		zap.Strings("req-headers", reqHeaders),
		zap.Strings("rsp-headers", rspHeaders))
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
