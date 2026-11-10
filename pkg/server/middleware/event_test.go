// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"storj.io/edge/pkg/server/gwlog"
	"storj.io/eventkit"
	"storj.io/eventkit/pb"
	"storj.io/gateway/api"
)

type eventRecorder struct {
	mu     sync.Mutex
	events []*eventkit.Event
}

func (r *eventRecorder) Submit(events ...*eventkit.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, events...)
}

func (r *eventRecorder) Run(ctx context.Context) {}

func (r *eventRecorder) tag(name, key string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, event := range r.events {
		if event.Name != name {
			continue
		}
		for _, tag := range event.Tags {
			if value, ok := tag.Value.(*pb.Tag_String_); ok && tag.Key == key {
				return string(value.String_), true
			}
		}
	}
	return "", false
}

func TestCollectEventErrorCode(t *testing.T) {
	var recorder eventRecorder
	eventkit.DefaultRegistry.AddDestination(&recorder)

	handler := CollectEvent(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log, ok := gwlog.FromContext(r.Context())
		require.True(t, ok)
		log.SetTags(api.ErrorCodeTag, "SlowDown")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/bucket/key", nil))

	code, ok := recorder.tag("gmt", "error-code")
	require.True(t, ok)
	require.Equal(t, "SlowDown", code)
}
