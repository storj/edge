// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"fmt"
	"net/http"
	"time"

	"github.com/spacemonkeygo/monkit/v3"

	"storj.io/gateway-mt/pkg/server/gwlog"
)

var mon = monkit.Package()

// StatusRecorder wraps ResponseWrite to store the HTTP response status code.
type StatusRecorder struct {
	http.ResponseWriter
	Status int
}

// Write implements Write to ensure HTTP 200s without making it default.
func (r *StatusRecorder) Write(data []byte) (int, error) {
	if r.Status == 0 {
		r.Status = 200
	}
	return r.ResponseWriter.Write(data)
}

// Flush implements Flusher, which is checked at runtime.
func (r *StatusRecorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// WriteHeader wraps ResponseWriter to store the status code.
func (r *StatusRecorder) WriteHeader(status int) {
	r.Status = status
	r.ResponseWriter.WriteHeader(status)
}

// Metrics sends metrics to Monkit, such as HTTP status code.
func Metrics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &StatusRecorder{ResponseWriter: w}

		ctx := r.Context()
		log, ok := gwlog.FromContext(ctx)
		if !ok {
			log = gwlog.New()
			r = r.WithContext(log.WithContext(ctx))
		}

		next.ServeHTTP(recorder, r)

		mon.DurationVal("gmt_request_times",
			monkit.NewSeriesTag("api", log.API),
			monkit.NewSeriesTag("status_code", fmt.Sprint(recorder.Status)),
		).Observe(time.Since(start))

		err := log.TagValue("error")
		if err != "" {
			mon.Event("gmt_unmapped_error",
				monkit.NewSeriesTag("api", log.API),
				monkit.NewSeriesTag("status_code", fmt.Sprint(recorder.Status)),
				monkit.NewSeriesTag("error", err),
			)
		}
	})
}
