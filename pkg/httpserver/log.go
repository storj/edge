// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package httpserver

import (
	stdlog "log"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/webhelp.v1/whmon"
	"gopkg.in/webhelp.v1/whroute"

	"storj.io/common/http/requestid"
	"storj.io/common/process/gcloudlogging"
	"storj.io/edge/pkg/httplog"
)

// clientErrorPrefixes are the net/http server errors that are entirely
// client-driven (aborted connections, port scanners, health checks, clients
// going away mid-stream) and too noisy to keep at info level.
var clientErrorPrefixes = []string{
	"http: TLS handshake error",
	"http2: server: error reading preface from client",
	"http2: received GOAWAY",
	"timeout waiting for SETTINGS frames from",
}

// newServerErrorLog returns a logger to be used as http.Server.ErrorLog. It
// behaves like zap.NewStdLog (logging at info level), except that
// client-driven errors are logged at debug level.
func newServerErrorLog(log *zap.Logger) *stdlog.Logger {
	// the same caller skip zap.NewStdLog uses, so that the caller still points
	// at net/http instead of at serverErrorWriter.Write.
	return stdlog.New(&serverErrorWriter{log: log.WithOptions(zap.AddCallerSkip(3))}, "", 0)
}

type serverErrorWriter struct {
	log *zap.Logger
}

func (w *serverErrorWriter) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\n")

	level := zapcore.InfoLevel
	for _, prefix := range clientErrorPrefixes {
		if strings.HasPrefix(msg, prefix) {
			level = zapcore.DebugLevel
			break
		}
	}

	if ce := w.log.Check(level, msg); ce != nil {
		ce.Write()
	}

	return len(p), nil
}

func logRequests(log *zap.Logger, h http.Handler) http.Handler {
	return whroute.HandlerFunc(h, func(w http.ResponseWriter, r *http.Request) {
		ce := log.Check(zap.DebugLevel, "access")
		if ce == nil {
			h.ServeHTTP(w, r)
			return
		}

		ce.Write([]zapcore.Field{
			gcloudlogging.LogHTTPRequest(&gcloudlogging.HTTPRequest{
				Protocol:      r.Proto,
				RequestMethod: r.Method,
				RequestSize:   r.ContentLength,
				UserAgent:     r.UserAgent(),
				RemoteIP:      ClientIP(r),
			}),
			zap.String("host", r.Host),
			// we are deliberately not logging the request URI as it has
			// sensitive information in it.
		}...)

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
				ce.Write([]zapcore.Field{
					gcloudlogging.LogHTTPRequest(&gcloudlogging.HTTPRequest{
						Protocol:      r.Proto,
						RequestMethod: method,
						RequestSize:   r.ContentLength,
						ResponseSize:  rw.Written(),
						UserAgent:     r.UserAgent(),
						RemoteIP:      ClientIP(r),
						Latency:       time.Since(start),
						Status:        rw.StatusCode(),
					}),
					// we are deliberately not logging the request URI as it has
					// sensitive information in it.
					zap.String("host", host),
					zap.String("request_id", requestid.FromContext(r.Context())),
					zap.String("trace_id", rw.Header().Get("trace-id")),
					zap.Object("request_headers", &httplog.HeadersLogObject{
						Headers: r.Header,
					}),
					zap.Object("response_headers", &httplog.HeadersLogObject{
						Headers: rw.Header(),
					}),
				}...)
			}
		}))
}
