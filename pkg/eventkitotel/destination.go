// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package eventkitotel

import (
	"context"
	"strings"

	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"

	"storj.io/eventkit"
	ekpb "storj.io/eventkit/pb"
)

// otelDestination is an eventkit.Destination which emits events as OpenTelemetry
// log records.
type otelDestination struct {
	logger otellog.Logger
}

// newOtelDestination creates a Destination reporting eventkit events through
// the given LoggerProvider.
func newOtelDestination(provider *sdklog.LoggerProvider) *otelDestination {
	return &otelDestination{
		logger: provider.Logger("eventkit"),
	}
}

// Submit converts each event into an OpenTelemetry log record and emits it.
func (d *otelDestination) Submit(events ...*eventkit.Event) {
	ctx := context.Background()
	for _, event := range events {
		var record otellog.Record
		record.SetTimestamp(event.Timestamp)
		record.SetSeverity(otellog.SeverityInfo)
		record.SetEventName(event.Name)
		record.SetBody(otellog.StringValue(event.Name))
		record.AddAttributes(
			otellog.String("name", event.Name),
			otellog.String("scope", strings.Join(event.Scope, ".")),
		)
		for _, tag := range event.Tags {
			record.AddAttributes(tagToKeyValue(tag))
		}
		d.logger.Emit(ctx, record)
	}
}

// Run is a no-op: records are emitted synchronously on Submit, and the
// underlying LoggerProvider owns batching and flushing. Shutting the provider
// down is the job of Shutdown.
func (d *otelDestination) Run(_ context.Context) {}

// tagToKeyValue converts an eventkit tag into an OpenTelemetry log attribute.
func tagToKeyValue(tag *ekpb.Tag) otellog.KeyValue {
	switch v := tag.Value.(type) {
	case *ekpb.Tag_String_:
		return otellog.String(tag.Key, string(v.String_))
	case *ekpb.Tag_Int64:
		return otellog.Int64(tag.Key, v.Int64)
	case *ekpb.Tag_Double:
		return otellog.Float64(tag.Key, v.Double)
	case *ekpb.Tag_Bytes:
		return otellog.Bytes(tag.Key, v.Bytes)
	case *ekpb.Tag_Bool:
		return otellog.Bool(tag.Key, v.Bool)
	case *ekpb.Tag_DurationNs:
		return otellog.Int64(tag.Key, v.DurationNs)
	case *ekpb.Tag_Timestamp:
		if v.Timestamp == nil {
			return otellog.Empty(tag.Key)
		}
		return otellog.Int64(tag.Key, v.Timestamp.Seconds*int64(1e9)+int64(v.Timestamp.Nanos))
	default:
		return otellog.Empty(tag.Key)
	}
}

var _ eventkit.Destination = (*otelDestination)(nil)
