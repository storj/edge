// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package eventkitotel

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"storj.io/eventkit"
)

// TestEndpointURL checks that the scheme carries the transport security and
// that the OTLP log path survives, since WithEndpointURL pins the path with the
// host and would otherwise lose the exporter's default.
func TestEndpointURL(t *testing.T) {
	for _, tt := range []struct {
		endpoint string
		secure   bool
		want     string
	}{
		{endpoint: "collector:4318", want: "http://collector:4318/v1/logs"},
		{endpoint: "collector:4318", secure: true, want: "https://collector:4318/v1/logs"},
		// a path in the configuration is kept as it is.
		{endpoint: "collector:4318/custom/logs", secure: true, want: "https://collector:4318/custom/logs"},
	} {
		got, err := endpointURL(tt.endpoint, tt.secure)
		require.NoError(t, err)
		require.Equal(t, tt.want, got)
	}

	// an invalid URL would silently leave otlploghttp on its localhost:4318
	// default, so it has to be reported instead.
	for _, endpoint := range []string{"", "[::1"} {
		_, err := endpointURL(endpoint, true)
		require.Error(t, err, "endpoint %q", endpoint)
	}
}

// TestLoggerProviderExports checks that events submitted to the destination
// reach an OTLP/HTTP endpoint once the provider is shut down.
func TestLoggerProviderExports(t *testing.T) {
	ctx := t.Context()

	type request struct {
		path string
		body []byte
	}
	requests := make(chan request, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		select {
		case requests <- request{path: r.URL.Path, body: body}:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	endpoint := strings.TrimPrefix(server.URL, "http://")

	provider, err := newLoggerProvider(ctx, endpoint, false, "test-app", "test-instance")
	require.NoError(t, err)

	newOtelDestination(provider).Submit(&eventkit.Event{
		Name:      "upload",
		Scope:     []string{"storj.io", "edge"},
		Timestamp: time.Now(),
		Tags:      []eventkit.Tag{eventkit.String("bucket", "test-bucket")},
	})

	// shutting the provider down flushes everything the batch processor holds.
	require.NoError(t, provider.Shutdown(ctx))

	select {
	case req := <-requests:
		require.Equal(t, "/v1/logs", req.path)
		// the payload is protobuf, but the string fields are readable in it.
		require.Contains(t, string(req.body), "upload")
		require.Contains(t, string(req.body), "test-bucket")
		require.Contains(t, string(req.body), "test-app")
		require.Contains(t, string(req.body), "test-instance")
	case <-time.After(10 * time.Second):
		t.Fatal("no OTLP request received")
	}
}
