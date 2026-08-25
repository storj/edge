// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package eventkitotel

import (
	"context"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"storj.io/eventkit"
)

// TestSetupFallsBackToUDP checks that an address without the otel: prefix still
// reaches eventkitd: the default of --metrics.event-addr is a bare host:port,
// and dropping those events would be silent telemetry loss.
func TestSetupFallsBackToUDP(t *testing.T) {
	for _, tt := range []struct {
		destConfig string
		udp        []string
	}{
		{destConfig: ""},
		{destConfig: "eventkitd.datasci.storj.io:9002", udp: []string{"eventkitd.datasci.storj.io:9002"}},
		{destConfig: "a:9002,b:9002", udp: []string{"a:9002", "b:9002"}},
		{destConfig: "otel:a:4318"},
		// only the addresses which are not OTLP endpoints go to eventkitd.
		{destConfig: "otel:a:4318, b:9002", udp: []string{"b:9002"}},
	} {
		t.Run(tt.destConfig, func(t *testing.T) {
			clients := collectUDPClients(t)

			registry := eventkit.NewRegistry()
			require.NoError(t, Setup(t.Context(), zaptest.NewLogger(t), tt.destConfig, registry, "test-app", "test-instance"))
			defer Shutdown(zap.NewNop())

			require.Equal(t, tt.udp, clients.addresses())
		})
	}
}

// TestSetupKeepsUsableDestinations checks that one unusable address does not
// take the usable ones with it. Setup registering nothing at all would be the
// silent telemetry loss the eventkitd fallback exists to prevent, and via
// Destination the error is only logged, so the process would keep running with
// no destination.
func TestSetupKeepsUsableDestinations(t *testing.T) {
	clients := collectUDPClients(t)

	registry := eventkit.NewRegistry()

	// "otel:" has no host:port and "bigquery:x" is gone, but the eventkitd
	// address next to them is fine.
	err := Setup(t.Context(), zaptest.NewLogger(t), "otel:,bigquery:x,eventkitd.datasci.storj.io:9002", registry, "test-app", "test-instance")
	defer Shutdown(zap.NewNop())

	require.Error(t, err)
	require.Contains(t, err.Error(), `"otel:"`)
	require.Contains(t, err.Error(), `"bigquery:x"`)

	require.Equal(t, []string{"eventkitd.datasci.storj.io:9002"}, clients.addresses())
}

// TestSetupRejectsBigQueryConfig checks that a bigquery configuration is
// recognised as a whole. Its commas separate its own parameters, so splitting
// it into addresses would take "project=test" for an eventkitd address.
func TestSetupRejectsBigQueryConfig(t *testing.T) {
	clients := collectUDPClients(t)

	registry := eventkit.NewRegistry()

	require.Error(t, Setup(t.Context(), zaptest.NewLogger(t),
		"bigquery:appName=test,project=test,dataset=test", registry, "test-app", "test-instance"))
	defer Shutdown(zap.NewNop())

	require.Empty(t, clients.addresses())
}

// TestShutdownFlushesUDP checks that Shutdown stops the eventkitd clients and
// waits for them. eventkit.UDPClient.Run only sends what is still queued in its
// ctx.Done() branch and otherwise flushes on a 15s jittered ticker, so a
// short-lived command (any authservice-admin command) would otherwise exit with
// its audit events still in the queue.
func TestShutdownFlushesUDP(t *testing.T) {
	clients := collectUDPClients(t)

	registry := eventkit.NewRegistry()
	require.NoError(t, Setup(t.Context(), zaptest.NewLogger(t), "a:9002,b:9002", registry, "test-app", "test-instance"))

	require.Equal(t, []string{"a:9002", "b:9002"}, clients.addresses())

	Shutdown(zaptest.NewLogger(t))

	// Shutdown returned, so every Run must have returned before it did, without
	// the caller's context having been cancelled.
	for _, client := range clients.all() {
		require.True(t, client.flushed.Load(), "Shutdown did not wait for %s to flush", client.address)
	}
}

// fakeUDPClients collects the eventkitd clients Setup creates.
type fakeUDPClients struct {
	mu      sync.Mutex
	clients []*fakeUDPClient
}

// collectUDPClients makes Setup build recording clients instead of real
// eventkit.UDPClients, so the fallback is testable without a UDP socket.
func collectUDPClients(t *testing.T) *fakeUDPClients {
	collected := &fakeUDPClients{}

	original := newUDPClient
	newUDPClient = func(_, _, _, address string) eventkit.Destination {
		client := &fakeUDPClient{address: address}

		collected.mu.Lock()
		defer collected.mu.Unlock()
		collected.clients = append(collected.clients, client)

		return client
	}
	t.Cleanup(func() { newUDPClient = original })

	return collected
}

func (c *fakeUDPClients) all() []*fakeUDPClient {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.clients)
}

func (c *fakeUDPClients) addresses() (addresses []string) {
	for _, client := range c.all() {
		addresses = append(addresses, client.address)
	}
	return addresses
}

// fakeUDPClient stands in for eventkit.UDPClient, recording that its Run
// returned rather than sending anything.
type fakeUDPClient struct {
	address string
	flushed atomic.Bool
}

func (c *fakeUDPClient) Submit(...*eventkit.Event) {}

func (c *fakeUDPClient) Run(ctx context.Context) {
	<-ctx.Done()
	// the real client drains its queue here, so a Shutdown which does not wait
	// for Run to return has to be able to lose the events: take long enough
	// that returning early is not just a scheduling race.
	time.Sleep(100 * time.Millisecond)
	c.flushed.Store(true)
}

// TestSetupRejectsUnusableConfig checks that a destination which cannot work is
// reported instead of being ignored.
func TestSetupRejectsUnusableConfig(t *testing.T) {
	for _, destConfig := range []string{
		"otel:",
		"otels:",
		"bigquery:app=test,project=test,dataset=test",
	} {
		t.Run(destConfig, func(t *testing.T) {
			original := newUDPClient
			newUDPClient = func(_, _, _, address string) eventkit.Destination {
				t.Fatalf("unusable destination fell back to UDP: %s", address)
				return nil
			}
			t.Cleanup(func() { newUDPClient = original })

			registry := eventkit.NewRegistry()

			require.Error(t, Setup(t.Context(), zaptest.NewLogger(t), destConfig, registry, "test-app", "test-instance"))

			// nothing was registered, so submitting must not panic or send.
			registry.Scope("test").Event("test")
			Shutdown(zap.NewNop())
		})
	}
}

// TestDestinationSendsToCollector checks the whole path: a config string picks
// the destination, events submitted to the registry reach the collector, and
// Shutdown flushes them.
func TestDestinationSendsToCollector(t *testing.T) {
	bodies := make(chan []byte, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		select {
		case bodies <- body:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	registry := eventkit.NewRegistry()
	destConfig := Prefix + strings.TrimPrefix(server.URL, "http://")

	Destination(t.Context(), zaptest.NewLogger(t), destConfig, registry, "test-app", "test-instance")

	registry.Scope("test").Event("upload", eventkit.String("bucket", "test-bucket"))

	Shutdown(zaptest.NewLogger(t))

	select {
	case body := <-bodies:
		require.Contains(t, string(body), "upload")
		require.Contains(t, string(body), "test-bucket")
		require.Contains(t, string(body), "test-app")
	case <-time.After(10 * time.Second):
		t.Fatal("no OTLP request received")
	}
}

// TestDestinationSendsToCollectorOverTLS checks that the otels: prefix selects
// an HTTPS connection to the collector.
func TestDestinationSendsToCollectorOverTLS(t *testing.T) {
	bodies := make(chan []byte, 1)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		select {
		case bodies <- body:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// the test server uses a self-signed certificate: trust it the same way an
	// operator would, through the OTLP environment configuration.
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_CERTIFICATE", writeServerCert(t, server.Certificate().Raw))

	// this package delegates the rest of the transport configuration to the
	// standard variables, so an operator may well have these set too. They must
	// not be able to downgrade otels:: without the scheme pinning the insecure
	// setting, otlploghttp resolves it from here and the events would leave over
	// plaintext HTTP, with the host still pinned to the flag.
	t.Setenv("OTEL_EXPORTER_OTLP_INSECURE", "true")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector.invalid:4318")

	registry := eventkit.NewRegistry()
	destConfig := SecurePrefix + strings.TrimPrefix(server.URL, "https://")

	require.NoError(t, Setup(t.Context(), zaptest.NewLogger(t), destConfig, registry, "test-app", "test-instance"))

	registry.Scope("test").Event("upload", eventkit.String("bucket", "test-bucket"))

	Shutdown(zaptest.NewLogger(t))

	select {
	case body := <-bodies:
		require.Contains(t, string(body), "upload")
		require.Contains(t, string(body), "test-bucket")
	case <-time.After(10 * time.Second):
		t.Fatal("no OTLP request received")
	}
}

// writeServerCert writes a DER certificate to a PEM file and returns its path.
func writeServerCert(t *testing.T, der []byte) string {
	path := filepath.Join(t.TempDir(), "collector.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	return path
}
