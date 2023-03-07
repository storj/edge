// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/webhelp.v1/whmon"
	"gopkg.in/webhelp.v1/whroute"

	"storj.io/common/grant"
	"storj.io/gateway-mt/pkg/auth/authdb"
	"storj.io/gateway-mt/pkg/httplog"
	"storj.io/gateway-mt/pkg/server/gwlog"
	"storj.io/gateway-mt/pkg/trustedip"
	xhttp "storj.io/minio/cmd/http"
	"storj.io/private/process/gcloudlogging"
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
		gcloudlogging.LogOperation(&gcloudlogging.Operation{
			ID:       gl.API,
			Producer: "storj.io/gateway-mt",
		}),
		zap.String("host", r.Host),
		zap.String("error", gl.TagValue("error")),
		zap.String("request-id", gl.RequestID),
		zap.String("encryption-key-hash", getEncryptionKeyHash(r)),
		zap.String("macaroon-head", getMacaroonHead(r)),
		zap.Strings("query", query),
		zap.Strings("req-headers", reqHeaders),
		zap.Strings("rsp-headers", rspHeaders),
	}

	if ce := log.Check(httplog.StatusLevel(rw.StatusCode()), "response"); ce != nil {
		ce.Write(fields...)
	}
}

// getMacaroonHead gets the macaroon head corresponding to the current request.
// Macaroon head is the best available criteria for associating a request to a user.
func getMacaroonHead(r *http.Request) string {
	credentials := GetAccess(r.Context())
	if credentials == nil || credentials.AccessGrant == "" {
		return ""
	}
	access, err := grant.ParseAccess(credentials.AccessGrant)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(access.APIKey.Head())
}

// getEncryptionKeyHash gets the encrypted Access Key ID corresponding to the current request.
func getEncryptionKeyHash(r *http.Request) string {
	credentials := GetAccess(r.Context())
	if credentials == nil || credentials.AccessKey == "" {
		return ""
	}

	var key authdb.EncryptionKey
	if err := key.FromBase32(credentials.AccessKey); err != nil {
		return ""
	}
	return key.Hash().ToHex()
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
