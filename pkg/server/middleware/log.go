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
	"storj.io/gateway-mt/pkg/server/gwlog"
	"storj.io/gateway-mt/pkg/trustedip"
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
			zap.String("remote-ip", getRemoteIP(r)),
			zap.Int64("request-content-length", r.ContentLength),
		}

		if insecureLogPaths {
			fields = append(fields, zap.String(requestURILogField, r.RequestURI))
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
	level := log.Debug
	if rw.StatusCode() >= 300 {
		level = log.Info
	} else if rw.StatusCode() >= 500 {
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
		zap.String("remote-ip", getRemoteIP(r)),
		zap.String("api", gl.API),
		zap.String("error", gl.TagValue("error")),
		zap.String("request-id", gl.RequestID),
		zap.String("encryption-key-hash", getEncryptionKeyHash(r)),
		zap.String("macaroon-head", getMacaroonHead(r)),
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
	level := log.Debug
	if rw.StatusCode() >= 300 {
		level = log.Info
	} else if rw.StatusCode() >= 500 {
		level = log.Error
	}

	fields := []zapcore.Field{
		zap.String("method", r.Method),
		zap.String("host", r.Host),
		zap.Int("code", rw.StatusCode()),
		zap.String("user-agent", r.UserAgent()),
		zap.String("remote-ip", getRemoteIP(r)),
		zap.Int64("content-length", r.ContentLength),
		zap.Int64("written", rw.Written()),
		zap.Duration("duration", d),
	}

	if insecureLogAll {
		fields = append(fields, zap.String(requestURILogField, r.RequestURI))
	}

	level("response", fields...)
}
