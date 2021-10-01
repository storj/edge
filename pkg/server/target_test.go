// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"testing"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"storj.io/minio/cmd/logger/message/log"
)

func TestSend(t *testing.T) {
	observedZapCore, observedLogs := observer.New(zap.InfoLevel)
	observedLogger := zap.New(observedZapCore)

	entry := log.Entry{
		API:   &log.API{Name: "SYSTEM"},
		Trace: &log.Trace{Message: "ohno!"},
	}
	lt := NewMinioSystemLogTarget(observedLogger)
	err := lt.Send(entry, "")
	require.NoError(t, err)

	c := monkit.Collect(monkit.ScopeNamed("storj.io/gateway-mt/pkg/server"))
	require.Equal(t, 1.0, c["gmt_unmapped_error,api=SYSTEM,error=ohno!,scope=storj.io/gateway-mt/pkg/server total"])

	filteredLogs := observedLogs.FilterField(zap.String("error", "ohno!"))
	require.Len(t, filteredLogs.All(), 1)
}

func TestSendRemoveAccessKey(t *testing.T) {
	observedZapCore, observedLogs := observer.New(zap.InfoLevel)
	observedLogger := zap.New(observedZapCore)

	entry := log.Entry{
		API:   &log.API{Name: "SYSTEM"},
		Trace: &log.Trace{Message: "Get \"http://localhost:8000/v1/access/12345\": dial tcp"},
	}
	lt := NewMinioSystemLogTarget(observedLogger)
	err := lt.Send(entry, "")
	require.NoError(t, err)

	filteredLogs := observedLogs.FilterField(zap.String("error", "Get \"http://localhost:8000/v1[...]\": dial tcp"))
	require.Len(t, filteredLogs.All(), 1)
}

func TestSendInvalidEntry(t *testing.T) {
	observedZapCore, observedLogs := observer.New(zap.InfoLevel)
	observedLogger := zap.New(observedZapCore)

	lt := NewMinioSystemLogTarget(observedLogger)
	err := lt.Send("", "")
	require.Error(t, err)

	err = lt.Send(log.Entry{}, "")
	require.Error(t, err)

	err = lt.Send(log.Entry{API: &log.API{Name: "SYSTEM"}}, "")
	require.Error(t, err)

	err = lt.Send(log.Entry{Trace: &log.Trace{Message: "test"}}, "")
	require.Error(t, err)

	require.Len(t, observedLogs.All(), 0)
}
