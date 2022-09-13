// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"

	"storj.io/common/rpc/rpctracing"
	"storj.io/gateway-mt/pkg/server/gwlog"
)

var mon = monkit.Package()

var (
	_ http.ResponseWriter = (*flusherDelegator)(nil)
	_ http.Flusher        = (*flusherDelegator)(nil)
)

// see: https://github.com/w3c/trace-context/blob/main/spec/20-http_request_header_format.md
const (
	traceSampled     = byte(1)
	traceFlagsHeader = "trace-flags"
	traceStateHeader = "tracestate"
	traceIDKey       = "trace-id"
)

// measureFunc is a common type for functions called at particular points of the
// request that we wish to measure, such as when a header is written. It receives
// the HTTP status code that was written as an argument.
type measureFunc func(int)

// flusherDelegator acts as a gatherer of status code and bytes written.
//
// It calls atWriteHeaderFunc only once for WriteHeader (so that
// atWriteHeaderFunc executes expectedly), but it still delegates WriteHeader
// from the caller. It's "illegal" to call WriteHeader twice, but we don't want
// to mask any bugs.
//
// flusherDelegator is loosely inspired by the design of
// prometheus/client_golang/prometheus/promhttp package.
type flusherDelegator struct {
	http.ResponseWriter

	// atWriteHeaderFunc is called at the call to WriteHeader.
	atWriteHeaderFunc measureFunc

	// atTimeToFirstByteFunc is called when bytes are first written.
	atTimeToFirstByteFunc measureFunc

	status                  int
	written                 int64
	wroteHeader             bool
	observedTimeToFirstByte bool
}

func (f *flusherDelegator) WriteHeader(code int) {
	if f.atWriteHeaderFunc != nil && !f.wroteHeader {
		f.atWriteHeaderFunc(code)
	}
	f.status = code
	f.wroteHeader = true
	f.ResponseWriter.WriteHeader(code)
}

func (f *flusherDelegator) Write(b []byte) (int, error) {
	if !f.wroteHeader {
		f.WriteHeader(http.StatusOK)
	}
	n, err := f.ResponseWriter.Write(b)
	if f.atTimeToFirstByteFunc != nil && !f.observedTimeToFirstByte {
		f.atTimeToFirstByteFunc(f.status)
		f.observedTimeToFirstByte = true
	}
	f.written += int64(n)
	return n, err
}

func (f flusherDelegator) Flush() {
	if !f.wroteHeader {
		f.WriteHeader(http.StatusOK)
	}
	f.ResponseWriter.(http.Flusher).Flush()
}

func makeMetricName(prefix, name string) string {
	return prefix + "_" + name
}

// sanitizeMethod returns a known HTTP method if m is such method. Otherwise, it
// returns "unknown".
//
// See https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods for known
// methods.
func sanitizeMethod(m string) string {
	switch m {
	case http.MethodGet, "get":
		return "get"
	case http.MethodPut, "put":
		return "put"
	case http.MethodHead, "head":
		return "head"
	case http.MethodPost, "post":
		return "post"
	case http.MethodDelete, "delete":
		return "delete"
	case http.MethodConnect, "connect":
		return "connect"
	case http.MethodOptions, "options":
		return "options"
	case "NOTIFY", "notify":
		return "notify"
	case http.MethodTrace, "trace":
		return "trace"
	case http.MethodPatch, "patch":
		return "patch"
	default:
		return "unknown"
	}
}

func parseTraceFlags(flag string) (byte, error) {
	decoded, err := hex.DecodeString(flag)
	if err != nil {
		return 0, errs.New("%s should be defined as HEX %s", traceFlagsHeader, err.Error())
	}
	if len(decoded) != 1 {
		return 0, errs.New("%s should be one byte", traceFlagsHeader)
	}
	return decoded[0], nil
}

// Metrics sends a bunch of useful metrics using monkit:
// - response time
// - time to write header
// - bytes written
// partitioned by method, status code, API.
//
// It also sends unmapped errors (in the case of Gateway-MT).
//
// TODO(artur): calculate approximate request size.
func Metrics(prefix string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		log, ok := gwlog.FromContext(ctx)
		if !ok {
			log = gwlog.New()
			r = r.WithContext(log.WithContext(ctx))
		}

		trace := monkit.NewTrace(monkit.NewId())
		flags := r.Header.Get(traceFlagsHeader)
		if flags != "" {
			parsed, err := parseTraceFlags(flags)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(err.Error()))
				return
			}
			if (parsed & traceSampled) == traceSampled {
				trace.Set(rpctracing.Sampled, true)
				w.Header().Set(traceStateHeader, fmt.Sprintf("%s=%x", traceIDKey, trace.Id()))
			}
		}

		ctx = r.Context()
		defer mon.Func().RemoteTrace(&ctx, 0, trace)(nil)
		r = r.WithContext(ctx)

		start := time.Now()

		mf := func(name string) measureFunc {
			return func(code int) {
				mon.DurationVal(
					makeMetricName(prefix, name),
					monkit.NewSeriesTag("api", log.API),
					monkit.NewSeriesTag("method", sanitizeMethod(r.Method)),
					monkit.NewSeriesTag("status_code", strconv.Itoa(code)),
				).Observe(time.Since(start))
			}
		}

		d := &flusherDelegator{
			ResponseWriter:        w,
			atWriteHeaderFunc:     mf("time_to_header"),
			atTimeToFirstByteFunc: mf("time_to_first_byte"),
		}

		next.ServeHTTP(d, r)
		took := time.Since(start)

		tags := []monkit.SeriesTag{
			monkit.NewSeriesTag("api", log.API),
			monkit.NewSeriesTag("method", sanitizeMethod(r.Method)),
			monkit.NewSeriesTag("status_code", strconv.Itoa(d.status)),
		}

		mon.DurationVal(makeMetricName(prefix, "response_time"), tags...).Observe(took)
		mon.IntVal(makeMetricName(prefix, "bytes_written"), tags...).Observe(d.written)
		mon.FloatVal(makeMetricName(prefix, "bps_written"), tags...).Observe(float64(d.written) / took.Seconds())

		if err := log.TagValue("error"); err != "" { // Gateway-MT-specific
			tags = append(tags, monkit.NewSeriesTag("error", err))
			mon.Event(makeMetricName(prefix, "unmapped_error"), tags...)
		}
	})
}

// NewMetrics is a convenience wrapper around Metrics that returns Metrics with
// prefix as mux.MiddlewareFunc.
func NewMetrics(prefix string) mux.MiddlewareFunc {
	return func(h http.Handler) http.Handler {
		return Metrics(prefix, h)
	}
}
