// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package httpserver

import (
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/webhelp.v1/whmon"
	"gopkg.in/webhelp.v1/whroute"

	"storj.io/common/http/requestid"
	"storj.io/gateway-mt/pkg/httplog"
	"storj.io/gateway-mt/pkg/trustedip"
	xhttp "storj.io/minio/cmd/http"
	"storj.io/private/process/gcloudlogging"
)

type headersLogObject struct {
	headers http.Header
}

func (o *headersLogObject) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	for k, v := range o.headers {
		var val string
		// obfuscate any credentials and sensitive information in headers.
		switch k {
		case xhttp.Authorization, "Cookie", xhttp.AmzCopySource:
			val = "[...]"
		default:
			val = strings.Join(v, ",")
		}
		enc.AddString(k, val)
	}
	return nil
}

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

			httpRequestLog := &gcloudlogging.HTTPRequest{
				Protocol:      r.Proto,
				RequestMethod: method,
				RequestSize:   r.ContentLength,
				ResponseSize:  rw.Written(),
				UserAgent:     r.UserAgent(),
				RemoteIP:      remoteIP(r),
				Latency:       time.Since(start),
				Status:        rw.StatusCode(),
			}

			fields := []zapcore.Field{
				gcloudlogging.LogHTTPRequest(httpRequestLog),
				// we are deliberately not logging the request URI as it has
				// sensitive information in it.
				zap.String("host", host),
				zap.String("request-id", requestid.FromContext(r.Context())),
				zap.Object("request-headers", &headersLogObject{
					headers: r.Header,
				}),
				zap.Object("response-headers", &headersLogObject{
					headers: rw.Header(),
				}),
			}

			if ce := log.Check(httplog.StatusLevel(rw.StatusCode()), "response"); ce != nil {
				ce.Write(fields...)
			}
		}))
}

func remoteIP(r *http.Request) string {
	return trustedip.GetClientIP(trustedip.NewListTrustAll(), r)
}
