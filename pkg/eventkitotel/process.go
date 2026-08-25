// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

// Package eventkitotel sends eventkit events to an OpenTelemetry collector as
// OpenTelemetry log records.
//
// It is a drop-in replacement of the eventkit destination selection of
// storj.io/common/process: addresses prefixed with "otel:" (or "otels:" for
// TLS) go to an OTLP/HTTP collector, anything else keeps going to eventkitd
// over UDP, exactly as before.
package eventkitotel

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/zeebo/errs"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.uber.org/zap"

	"storj.io/common/cfgstruct"
	"storj.io/common/process"
	"storj.io/common/version"
	"storj.io/eventkit"
)

const (
	// Prefix selects this destination in --metrics.event-addr, following the
	// convention of the "bigquery:" prefix it replaces. The collector is
	// contacted over plaintext OTLP/HTTP.
	Prefix = "otel:"

	// SecurePrefix selects the same destination over TLS (OTLP/HTTPS). The
	// client certificates and the extra headers are taken from the standard
	// OTEL_EXPORTER_OTLP_* environment variables.
	SecurePrefix = "otels:"

	// bigqueryPrefix is the destination which used to be selected by
	// storj.io/common/process. It is not supported here.
	bigqueryPrefix = "bigquery:"
)

// shutdownTimeout bounds how long flushing pending records may take at exit.
const shutdownTimeout = 10 * time.Second

// newUDPClient builds the eventkitd client non-OTLP addresses fall back to. It
// mirrors what process.UDPDestination constructs, which cannot be used here
// because it starts the client with an unwaited goroutine and returns no handle
// to it. It is a variable so the fallback can be tested without a UDP socket.
var newUDPClient = func(appName, appVersion, instanceID, address string) eventkit.Destination {
	client := eventkit.NewUDPClient(appName, appVersion, instanceID, address)
	client.QueueDepth = queueSize()
	return client
}

// udpRunner is a running eventkitd client Shutdown has to stop and wait for.
type udpRunner struct {
	cancel func()
	done   <-chan struct{}
}

var (
	mu        sync.Mutex
	providers []*sdklog.LoggerProvider
	runners   []udpRunner
)

// Destination reports eventkit events as OpenTelemetry log records to the
// OTLP/HTTP collector configured with --metrics.event-addr=otel:host:port.
//
// It implements process.InitEventkitDestination, so it is passed to
// process.InitMetrics instead of calling process.InitMetricsWithHostname.
// Errors can only be logged there; use Setup to handle them.
func Destination(ctx context.Context, log *zap.Logger, destConfig string, registry *eventkit.Registry, appName, instanceID string) {
	if err := Setup(ctx, log, destConfig, registry, appName, instanceID); err != nil {
		log.Error("Failed to set up eventkit destination, events are not collected",
			zap.String("destination", destConfig), zap.Error(err))
	}
}

// Setup is Destination with the error returned instead of logged, for commands
// which do not have a usable zap logger at this point.
//
// destConfig is the comma-separated address list of --metrics.event-addr. Every
// address prefixed with Prefix or SecurePrefix gets its own OTLP/HTTP exporter,
// the rest is handed to the eventkitd UDP destination unchanged, so a
// configuration which predates this package keeps working.
//
// An address which cannot be used does not stop the ones which can: every
// address is attempted, the failures are collected and returned together, so a
// list like "otel:,eventkitd.datasci.storj.io:9002" still ends up with a
// working eventkitd destination and only reports the unusable half. The one
// exception is a bigquery configuration, which is the whole value rather than
// one address of it.
func Setup(ctx context.Context, log *zap.Logger, destConfig string, registry *eventkit.Registry, appName, instanceID string) error {
	var udpAddresses []string
	var group errs.Group

	// the bigquery configuration is a "bigquery:appName=x,project=y,dataset=z"
	// list, so its commas separate its own parameters, not addresses, and
	// storj.io/common/process matched the prefix against the whole flag value
	// for exactly that reason. It has to be recognised before the split, or its
	// "project=y" half would be taken for an eventkitd address.
	if strings.HasPrefix(strings.TrimSpace(destConfig), bigqueryPrefix) {
		// falling back to UDP would send the events to an address which can
		// never resolve, so fail instead of losing them silently.
		return errs.New("eventkit destination %q is not supported anymore, use %shost:port", destConfig, Prefix)
	}

	for _, address := range strings.Split(destConfig, ",") {
		address = strings.TrimSpace(address)

		endpoint, secure := strings.CutPrefix(address, SecurePrefix)
		if !secure {
			endpoint, _ = strings.CutPrefix(address, Prefix)
		}
		isOtel := secure || strings.HasPrefix(address, Prefix)

		switch {
		case address == "":
		case isOtel:
			if endpoint == "" {
				group.Add(errs.New("eventkit destination %q has no host:port", address))
				continue
			}
			group.Add(addOtelDestination(ctx, log, endpoint, secure, registry, appName, instanceID))
		case strings.HasPrefix(address, bigqueryPrefix):
			// a bigquery config which is not the whole value: not something
			// process ever accepted, but do not treat it as an address either.
			group.Add(errs.New("eventkit destination %q is not supported anymore, use %shost:port", address, Prefix))
		default:
			udpAddresses = append(udpAddresses, address)
		}
	}

	if len(udpAddresses) > 0 {
		addUDPDestination(ctx, log, udpAddresses, registry, appName, instanceID)
	}

	return group.Err()
}

// addUDPDestination registers the eventkitd clients for the addresses which are
// not OTLP endpoints and starts them.
//
// The clients are started here rather than by process.UDPDestination because
// eventkit.UDPClient.Run only puts what is still queued on the wire in its
// ctx.Done() branch, and otherwise flushes on a 15s jittered ticker. Anything
// short-lived (the authservice-admin commands) would exit before that, so
// Shutdown has to be able to stop the clients and wait for that final flush,
// which needs a handle process.UDPDestination does not hand out.
func addUDPDestination(ctx context.Context, log *zap.Logger, addresses []string, registry *eventkit.Registry, appName, instanceID string) {
	// derived from the caller's context, so the clients stop either when it is
	// cancelled or when Shutdown is called, whichever comes first. Waiting on
	// the caller's context alone would deadlock Shutdown in a service which
	// shuts eventkit down before cancelling it.
	runCtx, cancel := context.WithCancel(ctx)

	appVersion := udpVersion()

	var wg sync.WaitGroup
	for _, address := range addresses {
		client := newUDPClient(appName, appVersion, instanceID, address)
		registry.AddDestination(client)

		wg.Go(func() {
			client.Run(runCtx)
		})
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	mu.Lock()
	runners = append(runners, udpRunner{cancel: cancel, done: done})
	mu.Unlock()

	log.Info("Sending eventkit events to eventkitd over UDP",
		zap.Strings("addresses", addresses),
		zap.String("service", appName),
		zap.String("instance", instanceID))
}

// udpVersion is the version string process.UDPDestination reports, replicated
// so the events look exactly the same as they did before this package.
func udpVersion() string {
	if cfgstruct.DefaultsType() == "release" {
		return version.Build.Version.String()
	}
	return version.Build.Timestamp.Format(time.RFC3339)
}

// addOtelDestination registers one OTLP/HTTP collector on the registry.
func addOtelDestination(ctx context.Context, log *zap.Logger, endpoint string, secure bool, registry *eventkit.Registry, appName, instanceID string) error {
	provider, err := newLoggerProvider(ctx, endpoint, secure, appName, instanceID)
	if err != nil {
		return errs.Wrap(err)
	}

	registry.AddDestination(newOtelDestination(provider))

	mu.Lock()
	providers = append(providers, provider)
	mu.Unlock()

	log.Info("Sending eventkit events to OpenTelemetry collector",
		zap.String("endpoint", endpoint),
		zap.Bool("tls", secure),
		zap.String("service", appName),
		zap.String("instance", instanceID))

	return nil
}

// Shutdown flushes the events collected so far and shuts the exporters down. It
// must be deferred by the caller: whatever the batch processor still holds is
// dropped when the process exits otherwise.
func Shutdown(log *zap.Logger) {
	mu.Lock()
	pending := providers
	providers = nil
	pendingRunners := runners
	runners = nil
	mu.Unlock()

	// the eventkitd clients send what is still queued only once their context
	// is done, so stopping them is what triggers the flush, and the events are
	// not on the wire until Run has returned.
	for _, runner := range pendingRunners {
		runner.cancel()
	}
	if len(pendingRunners) > 0 {
		timeout := time.NewTimer(shutdownTimeout)
	wait:
		for _, runner := range pendingRunners {
			select {
			case <-runner.done:
			case <-timeout.C:
				log.Warn("Timed out flushing eventkit events to eventkitd")
				break wait
			}
		}
		timeout.Stop()
	}

	for _, provider := range pending {
		// the context the destination was created with is usually canceled by
		// the time we shut down, but the pending records should still be sent.
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		if err := provider.Shutdown(ctx); err != nil {
			log.Warn("Failed to flush eventkit events", zap.Error(err))
		}
		cancel()
	}
}

var _ process.InitEventkitDestination = Destination
