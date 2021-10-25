// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/webhelp.v1/whmon"
	"gopkg.in/webhelp.v1/whroute"

	"storj.io/gateway-mt/pkg/server/gwlog"
	xhttp "storj.io/minio/cmd/http"
)

const requestURILogField = "request-uri"

// LogRequests logs requests.
func LogRequests(log *zap.Logger, h http.Handler, insecureLogPaths bool) http.Handler {
	return whroute.HandlerFunc(h, func(w http.ResponseWriter, r *http.Request) {
		fields := []zapcore.Field{
			zap.String("protocol", r.Proto),
			zap.String("method", r.Method),
			zap.String("host", r.Host),
			zap.String("user-agent", r.UserAgent()),
		}

		if insecureLogPaths {
			fields = append(fields, zap.String(requestURILogField, r.RequestURI))
		}

		log.Info("access", fields...)
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

func logGatewayResponse(log *zap.Logger, r *http.Request, rw whmon.ResponseWriter, gl *gwlog.Log, d time.Duration, insecureLogAll bool) {
	level := log.Info
	if rw.StatusCode() >= 500 {
		level = log.Error
	}

	var query []string
	for k, v := range r.URL.Query() {
		if insecureLogAll {
			query = append(query, fmt.Sprintf("%s=%s", k, strings.Join(v, ",")))
			continue
		}

		var val string
		// obfuscate any credentials or confidential information in the query value.
		// https://docs.aws.amazon.com/general/latest/gr/signature-version-2.html
		// https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
		switch k {
		case "prefix", xhttp.AmzAccessKeyID, xhttp.AmzSignatureV2, xhttp.AmzSignature, xhttp.AmzCredential:
			val = "[...]"
		default:
			val = strings.Join(v, ",")
		}
		query = append(query, fmt.Sprintf("%s=%s", k, val))
	}

	var reqHeaders []string
	for k, v := range r.Header {
		if insecureLogAll {
			reqHeaders = append(reqHeaders, fmt.Sprintf("%s=%s", k, strings.Join(v, ",")))
			continue
		}

		var val string
		// obfuscate any credentials and sensitive information in headers.
		switch k {
		case xhttp.Authorization, "Cookie", xhttp.AmzCopySource:
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

	fields := []zapcore.Field{
		zap.String("protocol", r.Proto),
		zap.String("method", r.Method),
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
		zap.Strings("rsp-headers", rspHeaders),
	}

	if insecureLogAll {
		fields = append(fields, zap.String(requestURILogField, r.RequestURI))
	}

	level("response", fields...)
}

func logResponse(log *zap.Logger, r *http.Request, rw whmon.ResponseWriter, d time.Duration, insecureLogAll bool) {
	level := log.Info
	if rw.StatusCode() >= 500 {
		level = log.Error
	}

	fields := []zapcore.Field{
		zap.String("method", r.Method),
		zap.String("host", r.Host),
		zap.Int("code", rw.StatusCode()),
		zap.String("user-agent", r.UserAgent()),
		zap.Int64("content-length", r.ContentLength),
		zap.Int64("written", rw.Written()),
		zap.Duration("duration", d),
	}

	if insecureLogAll {
		fields = append(fields, zap.String(requestURILogField, r.RequestURI))
	}

	level("response", fields...)
}
