// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"storj.io/common/testcontext"
	"storj.io/gateway-mt/pkg/server/gwlog"
)

func TestMetrics(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	const bytesWritten = 12

	status := func(code int) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if log, ok := gwlog.FromContext(r.Context()); ok {
				log.API = "ListObjects"
				log.SetTags("error", "error!")
			}

			w.WriteHeader(code)
			_, err := w.Write(make([]byte, bytesWritten))
			require.NoError(t, err)

			w.(http.Flusher).Flush()
		})
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "", nil)
	assert.NoError(t, err)
	rr := httptest.NewRecorder()

	Metrics("gmt", status(200)).ServeHTTP(rr, req) // 1 200
	Metrics("gmt", status(400)).ServeHTTP(rr, req) // 2 400s
	Metrics("gmt", status(400)).ServeHTTP(rr, req)
	Metrics("gmt", status(500)).ServeHTTP(rr, req) // 3 500s
	Metrics("gmt", status(500)).ServeHTTP(rr, req)
	Metrics("gmt", status(500)).ServeHTTP(rr, req)

	c := monkit.Collect(monkit.ScopeNamed("storj.io/gateway-mt/pkg/server/middleware"))

	for _, v := range []string{"time_to_first_byte", "response_time", "time_to_header", "bytes_written"} {
		assert.Equal(t, 1.0, c[fmt.Sprintf("gmt_%s,api=ListObjects,method=get,scope=storj.io/gateway-mt/pkg/server/middleware,status_code=200 count", v)])
		assert.Equal(t, 2.0, c[fmt.Sprintf("gmt_%s,api=ListObjects,method=get,scope=storj.io/gateway-mt/pkg/server/middleware,status_code=400 count", v)])
		assert.Equal(t, 3.0, c[fmt.Sprintf("gmt_%s,api=ListObjects,method=get,scope=storj.io/gateway-mt/pkg/server/middleware,status_code=500 count", v)])
	}

	assert.EqualValues(t, bytesWritten, c["gmt_bytes_written,api=ListObjects,method=get,scope=storj.io/gateway-mt/pkg/server/middleware,status_code=200 sum"])
	assert.EqualValues(t, bytesWritten, c["gmt_bytes_written,api=ListObjects,method=get,scope=storj.io/gateway-mt/pkg/server/middleware,status_code=200 recent"])
	assert.EqualValues(t, 2*bytesWritten, c["gmt_bytes_written,api=ListObjects,method=get,scope=storj.io/gateway-mt/pkg/server/middleware,status_code=400 sum"])
	assert.EqualValues(t, bytesWritten, c["gmt_bytes_written,api=ListObjects,method=get,scope=storj.io/gateway-mt/pkg/server/middleware,status_code=400 recent"])
	assert.EqualValues(t, 3*bytesWritten, c["gmt_bytes_written,api=ListObjects,method=get,scope=storj.io/gateway-mt/pkg/server/middleware,status_code=500 sum"])
	assert.EqualValues(t, bytesWritten, c["gmt_bytes_written,api=ListObjects,method=get,scope=storj.io/gateway-mt/pkg/server/middleware,status_code=500 recent"])
}
