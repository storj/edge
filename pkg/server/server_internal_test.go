// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/accesslogs"
	"storj.io/common/memory"
	"storj.io/common/testcontext"
	"storj.io/edge/pkg/httpserver"
)

func TestDeduplicateDomains(t *testing.T) {
	test := func(input string, expected []string) {
		output := deduplicateDomains(input)
		sort.Strings(expected)
		sort.Strings(output)
		require.Equal(t, expected, output)
	}

	test("gateway.local,gateway.local", []string{"gateway.local"})
	test("gateway.local,*.gateway.local", []string{"gateway.local"})
	test("gateway.local,*.gateway.local,test.com,*.test.com", []string{"gateway.local", "test.com"})
	test("gateway.local,*.gateway.local,*.gateway2.local", []string{"gateway.local", "gateway2.local"})
}

// TestRunStopsWhenServerFails verifies that a failure to start the HTTP server
// makes Run return instead of hanging forever waiting for the access logs
// processor, which only returns from Run once it's closed.
func TestRunStopsWhenServerFails(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	log := zaptest.NewLogger(t)

	// an unresolvable satellite makes the startup check, and therefore
	// httpserver.Server.Run, fail before any listener is served.
	server, err := httpserver.New(log, http.NotFoundHandler(), nil, httpserver.Config{
		Address: "127.0.0.1:0",
		StartupCheckConfig: httpserver.StartupCheckConfig{
			Enabled:    true,
			Satellites: []string{"not-a-node-url"},
			Timeout:    time.Second,
		},
	})
	require.NoError(t, err)

	peer := Peer{
		log:       log,
		processor: accesslogs.NewProcessor(log, accesslogs.Options{}),
		server:    server,
		// minioOnce is shared with the tests in package server_test, which
		// also run Peer.Run, so this test must not consume it with a no-op:
		// that would leave Minio uninitialized for the rest of the binary.
		// InsecureDisableTLS matches what those tests set up first today, so
		// whichever of them wins the once, minio.GlobalIsTLS ends up the same.
		config:     Config{InsecureDisableTLS: true},
		closeLayer: func(context.Context) error { return nil },
	}

	// deliberately not ctx.Go: if Run deadlocks, this goroutine never
	// finishes, and waiting for it would hang the whole test binary rather
	// than failing this test.
	done := make(chan error, 1)
	go func() { done <- peer.Run(ctx) }()

	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return after the HTTP server failed to start")
	}
}

// TestCloseDrainsBeforeClosingProcessor verifies that a regular shutdown keeps
// the access logs processor open while httpserver.Shutdown is draining
// in-flight requests. Shutdown closes the listeners first, so
// httpserver.Server.Run returns while handlers are still running, and those
// handlers still queue access log entries after ServeHTTP returns.
func TestCloseDrainsBeforeClosingProcessor(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	log := zaptest.NewLogger(t)

	inHandler, releaseHandler := make(chan struct{}), make(chan struct{})
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(inHandler)
		<-releaseHandler
	})

	server, err := httpserver.New(log, handler, nil, httpserver.Config{
		Address: "127.0.0.1:0",
		// generous, so that the drain outlives the assertions below.
		ShutdownTimeout: time.Minute,
	})
	require.NoError(t, err)

	peer := Peer{
		log:        log,
		processor:  accesslogs.NewProcessor(log, accesslogs.Options{}),
		server:     server,
		config:     Config{InsecureDisableTLS: true},
		closeLayer: func(context.Context) error { return nil },
	}
	addr := peer.Address()

	runDone := make(chan error, 1)
	go func() { runDone <- peer.Run(ctx) }()

	// keep one request in flight, so that Shutdown has something to drain.
	reqDone := make(chan error, 1)
	go func() {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/", nil)
		if err != nil {
			reqDone <- err
			return
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
		reqDone <- err
	}()
	<-inHandler

	// queue one entry up front, so that the parcel for this key exists: an
	// entry for an unknown key is silently buffered into a parcel nobody
	// flushes rather than rejected, and wouldn't report the processor state.
	key := accesslogs.Key{Bucket: "bucket", Prefix: "prefix"}
	require.NoError(t, peer.processor.QueueEntry(noopStorage{}, key, testEntry("first")))

	closeDone := make(chan error, 1)
	go func() { closeDone <- peer.Close() }()

	// wait for Shutdown to close the listeners, which is what makes
	// httpserver.Server.Run return while the handler above still runs.
	require.Eventually(t, func() bool {
		dialer := net.Dialer{Timeout: time.Second}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return true
		}
		return conn.Close() != nil
	}, 30*time.Second, 10*time.Millisecond, "listeners were never closed")

	// the request is still draining, so its entry must still be accepted.
	require.Never(t, func() bool {
		return errors.Is(peer.processor.QueueEntry(noopStorage{}, key, testEntry("draining")), accesslogs.ErrClosed)
	}, 2*time.Second, 50*time.Millisecond, "processor was closed before the drain finished")

	close(releaseHandler)
	require.NoError(t, <-reqDone)
	require.NoError(t, <-closeDone)
	require.NoError(t, <-runDone)

	// Close owns closing the processor, and has done so by now.
	require.ErrorIs(t, peer.processor.QueueEntry(noopStorage{}, key, testEntry("after")), accesslogs.ErrClosed)
}

type noopStorage struct{}

func (noopStorage) Put(context.Context, string, string, []byte) error { return nil }

type testEntry string

func (e testEntry) Size() memory.Size { return memory.Size(len(e)) }
func (e testEntry) String() string    { return string(e) }
