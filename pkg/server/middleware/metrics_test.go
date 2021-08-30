// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/stretchr/testify/assert"

	"storj.io/common/testcontext"
	"storj.io/gateway-mt/pkg/server/gwlog"
)

func TestMetrics(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	status := func(code int) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if log, ok := gwlog.FromContext(r.Context()); ok {
				log.API = "ListObjects"
				log.SetTags("error", "error!")
			}

			w.WriteHeader(code)
		})
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "", nil)
	assert.NoError(t, err)
	rr := httptest.NewRecorder()

	Metrics(status(200)).ServeHTTP(rr, req) // 1 200
	Metrics(status(400)).ServeHTTP(rr, req) // 2 400s
	Metrics(status(400)).ServeHTTP(rr, req)
	Metrics(status(500)).ServeHTTP(rr, req) // 3 500s
	Metrics(status(500)).ServeHTTP(rr, req)
	Metrics(status(500)).ServeHTTP(rr, req)

	c := monkit.Collect(monkit.ScopeNamed("storj.io/gateway-mt/pkg/server/middleware"))
	assert.Equal(t, 1.0, c["gmt_request_times,api=ListObjects,scope=storj.io/gateway-mt/pkg/server/middleware,status_code=200 count"])
	assert.Equal(t, 2.0, c["gmt_request_times,api=ListObjects,scope=storj.io/gateway-mt/pkg/server/middleware,status_code=400 count"])
	assert.Equal(t, 3.0, c["gmt_request_times,api=ListObjects,scope=storj.io/gateway-mt/pkg/server/middleware,status_code=500 count"])
	assert.Equal(t, 1.0, c["gmt_unmapped_error,api=ListObjects,error=error!,scope=storj.io/gateway-mt/pkg/server/middleware,status_code=200 total"])
	assert.Equal(t, 2.0, c["gmt_unmapped_error,api=ListObjects,error=error!,scope=storj.io/gateway-mt/pkg/server/middleware,status_code=400 total"])
	assert.Equal(t, 3.0, c["gmt_unmapped_error,api=ListObjects,error=error!,scope=storj.io/gateway-mt/pkg/server/middleware,status_code=500 total"])
}
