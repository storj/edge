// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"net/http"
	"regexp"

	"github.com/spacemonkeygo/monkit/v3"

	"storj.io/common/rpc/rpctracing"
)

// TraceHostHeader is the HTTP header with the address of the collector which
// should receive the spans of the request's trace.
const TraceHostHeader = "X-Storj-Trace-Host"

// TraceHost sets the collector address from TraceHostHeader on the request's
// trace, if the trace is sampled and the address matches hostRegex. The
// address is propagated over DRPC, so the satellite and storage nodes send
// their spans of the trace there too.
//
// It must be used after the handler that imports the trace from the request.
func TraceHost(hostRegex *regexp.Regexp) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if host := r.Header.Get(TraceHostHeader); host != "" && hostRegex != nil && hostRegex.MatchString(host) {
				if span := monkit.SpanFromCtx(r.Context()); span != nil {
					trace := span.Trace()
					if sampled, _ := trace.Get(rpctracing.Sampled).(bool); sampled {
						trace.Set(rpctracing.TraceHost, host)
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
