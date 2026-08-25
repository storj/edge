// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package eventkitotel

import (
	"context"
	"flag"
	"net/url"

	"github.com/zeebo/errs"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.30.0"

	"storj.io/common/version"
)

// queueFlag is the flag registered by storj.io/common/process for the outgoing
// queue of the UDP destination. It is reused here so operators have a single
// knob for the eventkit queue depth, whichever destination is configured.
const queueFlag = "metrics.event-queue"

// defaultQueueSize is used when queueFlag is not registered, which happens when
// the destination is set up outside of process.InitMetrics (in tests).
const defaultQueueSize = 10000

// defaultPath is the OTLP/HTTP path for log records, the same value
// otlploghttp would have defaulted to. It has to be spelled out because
// WithEndpointURL pins the path together with the host.
const defaultPath = "/v1/logs"

// newLoggerProvider creates a LoggerProvider which sends OpenTelemetry log
// records to an OTLP/HTTP endpoint. With secure set, the connection is TLS
// protected, otherwise it is plaintext HTTP.
//
// The provider is dedicated to eventkit and is deliberately not registered as
// the global OpenTelemetry LoggerProvider: it should only ever see the records
// generated from eventkit events.
func newLoggerProvider(ctx context.Context, endpoint string, secure bool, appName, instanceID string) (*sdklog.LoggerProvider, error) {
	endpointURL, err := endpointURL(endpoint, secure)
	if err != nil {
		return nil, err
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(appName),
			semconv.ServiceVersion(version.Build.Version.String()),
			semconv.ServiceInstanceID(instanceID),
		),
	)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	// only the endpoint and the transport security are pinned here, everything
	// else (client certificates, authorization headers, compression, timeout)
	// is left to the standard OTEL_EXPORTER_OTLP_* environment variables, which
	// the exporter honours for the options it was not given.
	exporter, err := otlploghttp.New(ctx, otlploghttp.WithEndpointURL(endpointURL))
	if err != nil {
		return nil, errs.Wrap(err)
	}

	// the batch processor is what keeps Submit off the network: it enqueues the
	// record and a background goroutine does the exporting, the same role the
	// outgoing queue plays for the UDP destination.
	return sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter,
			sdklog.WithMaxQueueSize(queueSize()),
		)),
	), nil
}

// endpointURL turns the host:port of an otel:/otels: address into the URL
// otlploghttp.WithEndpointURL expects.
//
// The scheme is what pins the transport security, and that is the whole point
// of going through a URL: WithEndpoint only sets the host, so for the secure
// case the insecure setting would be left unset and otlploghttp's newConfig
// would then resolve it from OTEL_EXPORTER_OTLP[_LOGS]_ENDPOINT or
// OTEL_EXPORTER_OTLP_INSECURE. Since this package deliberately delegates the
// rest of the transport configuration to those variables, an operator who sets
// an http:// endpoint or OTEL_EXPORTER_OTLP_INSECURE=true there would get
// plaintext out of "otels:", with the host still pinned to the flag. An
// explicit scheme resolves the setting up front (insecureFromScheme), so the
// environment can no longer downgrade it.
func endpointURL(endpoint string, secure bool) (_ string, err error) {
	scheme := "http"
	if secure {
		scheme = "https"
	}

	// an invalid URL makes WithEndpointURL keep the localhost:4318 default and
	// only report to the global otel error handler, so parse it here to fail
	// where the error can still be returned to the caller.
	u, err := url.Parse(scheme + "://" + endpoint)
	if err != nil {
		return "", errs.New("eventkit destination %q is not a valid host:port: %v", endpoint, err)
	}
	if u.Host == "" {
		return "", errs.New("eventkit destination %q has no host:port", endpoint)
	}
	if u.Path == "" {
		u.Path = defaultPath
	}

	return u.String(), nil
}

// queueSize returns the configured depth of the outgoing queue. The flag is
// looked up by name because it is registered by storj.io/common/process, which
// does not export it.
func queueSize() int {
	f := flag.Lookup(queueFlag)
	if f == nil {
		return defaultQueueSize
	}
	getter, ok := f.Value.(flag.Getter)
	if !ok {
		return defaultQueueSize
	}
	size, ok := getter.Get().(int)
	if !ok || size <= 0 {
		return defaultQueueSize
	}
	return size
}
