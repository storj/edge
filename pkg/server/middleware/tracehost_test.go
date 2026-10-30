// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/spacemonkeygo/monkit/v3"
	mhttp "github.com/spacemonkeygo/monkit/v3/http"
	"github.com/stretchr/testify/require"

	"storj.io/common/rpc/rpctracing"
)

func TestTraceHost(t *testing.T) {
	hostRegex := regexp.MustCompile(`\.storj\.tools:[0-9]+$`)

	for _, tt := range []struct {
		name     string
		header   http.Header
		wantHost string
	}{
		{
			name:     "sampled with allowed host",
			header:   http.Header{"Tracestate": {"sampled=true"}, TraceHostHeader: {"jaeger.storj.tools:5775"}},
			wantHost: "jaeger.storj.tools:5775",
		},
		{
			name:     "traceparent with allowed host",
			header:   http.Header{"Traceparent": {"00-0000000000000001-0000000000000002-01"}, TraceHostHeader: {"jaeger.storj.tools:5775"}},
			wantHost: "jaeger.storj.tools:5775",
		},
		{
			name:   "sampled with not allowed host",
			header: http.Header{"Tracestate": {"sampled=true"}, TraceHostHeader: {"example.com:5775"}},
		},
		{
			name:   "not sampled",
			header: http.Header{TraceHostHeader: {"jaeger.storj.tools:5775"}},
		},
		{
			name:   "no host",
			header: http.Header{"Tracestate": {"sampled=true"}},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var called bool
			verify := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				span := monkit.SpanFromCtx(r.Context())
				require.NotNil(t, span)
				host, _ := span.Trace().Get(rpctracing.TraceHost).(string)
				require.Equal(t, tt.wantHost, host)
			})

			req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/bucket/key", nil)
			req.Header = tt.header

			mhttp.TraceHandler(TraceHost(hostRegex)(verify), monkit.Package()).ServeHTTP(httptest.NewRecorder(), req)
			require.True(t, called)
		})
	}
}
