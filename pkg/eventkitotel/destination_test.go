// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package eventkitotel

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"

	"storj.io/eventkit"
	ekpb "storj.io/eventkit/pb"
)

// memoryExporter collects exported log records in memory for assertions.
type memoryExporter struct {
	mu      sync.Mutex
	records []sdklog.Record
}

func (e *memoryExporter) Export(ctx context.Context, records []sdklog.Record) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, r := range records {
		e.records = append(e.records, r.Clone())
	}
	return nil
}

func (e *memoryExporter) Shutdown(ctx context.Context) error   { return nil }
func (e *memoryExporter) ForceFlush(ctx context.Context) error { return nil }

func (e *memoryExporter) collected() []sdklog.Record {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]sdklog.Record, len(e.records))
	copy(out, e.records)
	return out
}

// attrs collects the attributes of a record into a map for easier assertions.
func attrs(record sdklog.Record) map[string]otellog.Value {
	out := make(map[string]otellog.Value)
	record.WalkAttributes(func(kv otellog.KeyValue) bool {
		out[kv.Key] = kv.Value
		return true
	})
	return out
}

func TestDestinationSubmit(t *testing.T) {
	exporter := &memoryExporter{}
	provider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewSimpleProcessor(exporter)),
	)

	timestamp := time.Date(2026, 8, 25, 10, 30, 0, 0, time.UTC)

	newOtelDestination(provider).Submit(&eventkit.Event{
		Name:      "upload",
		Scope:     []string{"storj.io", "edge", "pkg"},
		Timestamp: timestamp,
		Tags: []eventkit.Tag{
			eventkit.String("bucket", "test-bucket"),
			eventkit.Int64("size", 1024),
			eventkit.Float64("ratio", 0.5),
			eventkit.Bytes("checksum", []byte{1, 2, 3}),
			eventkit.Bool("cached", true),
			eventkit.Duration("elapsed", 3*time.Second),
			eventkit.Timestamp("started", timestamp),
		},
	})

	records := exporter.collected()
	require.Len(t, records, 1)

	record := records[0]
	require.Equal(t, timestamp, record.Timestamp())
	require.Equal(t, otellog.SeverityInfo, record.Severity())
	require.Equal(t, "upload", record.EventName())
	require.Equal(t, "upload", record.Body().AsString())

	got := attrs(record)
	require.Equal(t, "upload", got["name"].AsString())
	require.Equal(t, "storj.io.edge.pkg", got["scope"].AsString())
	require.Equal(t, "test-bucket", got["bucket"].AsString())
	require.Equal(t, int64(1024), got["size"].AsInt64())
	require.InDelta(t, 0.5, got["ratio"].AsFloat64(), 1e-9)
	require.Equal(t, []byte{1, 2, 3}, got["checksum"].AsBytes())
	require.True(t, got["cached"].AsBool())
	require.Equal(t, int64(3*time.Second), got["elapsed"].AsInt64())
	require.Equal(t, timestamp.UnixNano(), got["started"].AsInt64())
}

// TestDestinationSubmitNilTimestamp checks that a timestamp tag without a value
// is reported as an empty attribute instead of panicking.
func TestDestinationSubmitNilTimestamp(t *testing.T) {
	exporter := &memoryExporter{}
	provider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewSimpleProcessor(exporter)),
	)

	newOtelDestination(provider).Submit(&eventkit.Event{
		Name:  "upload",
		Scope: []string{"storj.io", "edge"},
		Tags: []eventkit.Tag{
			{Key: "started", Value: &ekpb.Tag_Timestamp{}},
		},
	})

	records := exporter.collected()
	require.Len(t, records, 1)
	require.Equal(t, otellog.KindEmpty, attrs(records[0])["started"].Kind())
}

func TestDestinationSubmitMultiple(t *testing.T) {
	exporter := &memoryExporter{}
	provider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewSimpleProcessor(exporter)),
	)

	newOtelDestination(provider).Submit(
		&eventkit.Event{Name: "first", Scope: []string{"a"}},
		&eventkit.Event{Name: "second", Scope: []string{"b"}},
	)

	records := exporter.collected()
	require.Len(t, records, 2)
	require.Equal(t, "first", records[0].EventName())
	require.Equal(t, "second", records[1].EventName())
}
