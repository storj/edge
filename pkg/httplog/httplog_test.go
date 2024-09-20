// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package httplog

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"storj.io/common/testcontext"
	xhttp "storj.io/minio/cmd/http"
)

func TestStatusLevel(t *testing.T) {
	testCases := []struct {
		status        int
		expectedLevel zapcore.Level
	}{
		{
			status:        http.StatusOK,
			expectedLevel: zap.DebugLevel,
		},
		{
			status:        http.StatusCreated,
			expectedLevel: zap.DebugLevel,
		},
		{
			status:        http.StatusMultipleChoices,
			expectedLevel: zap.DebugLevel,
		},
		{
			status:        http.StatusPermanentRedirect,
			expectedLevel: zap.DebugLevel,
		},
		{
			status:        http.StatusBadRequest,
			expectedLevel: zap.DebugLevel,
		},
		{
			status:        http.StatusNotFound,
			expectedLevel: zap.DebugLevel,
		},
		{
			status:        http.StatusInternalServerError,
			expectedLevel: zap.ErrorLevel,
		},
		{
			status:        http.StatusBadGateway,
			expectedLevel: zap.ErrorLevel,
		},
		{
			status:        http.StatusNotImplemented,
			expectedLevel: zap.WarnLevel,
		},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(fmt.Sprintf("HTTP %d response logged as %s", tc.status, tc.expectedLevel), func(t *testing.T) {
			require.Equal(t, tc.expectedLevel, StatusLevel(tc.status))
		})
	}
}

func TestConfidentialLogFields(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	tests := []struct {
		header string
		query  string
	}{
		{query: xhttp.AmzAccessKeyID, header: ""},
		{query: xhttp.AmzSignatureV2, header: ""},
		{query: xhttp.AmzSignature, header: ""},
		{query: xhttp.AmzCredential, header: ""},
		{query: "prefix", header: ""},
		{header: xhttp.Authorization, query: ""},
		{header: "Cookie", query: ""},
		{header: xhttp.AmzCopySource, query: ""},
		{query: "delimiter", header: ""},
	}
	for i, test := range tests {
		observedZapCore, observedLogs := observer.New(zap.DebugLevel)
		observedLogger := zap.New(observedZapCore)

		observedLogger.Debug("hello",
			zap.Object("headers", &HeadersLogObject{Headers: http.Header{test.header: []string{"value"}}}),
			zap.Object("query", &RequestQueryLogObject{Query: url.Values{test.query: []string{"value"}}}))

		if test.header != "" {
			require.Len(t, observedLogs.All(), 1, i)
			fields, ok := observedLogs.All()[0].ContextMap()["headers"].(map[string]interface{})
			require.True(t, ok, i)
			require.Equal(t, "[...]", fields[test.header], i)
		}

		if test.query != "" {
			require.Len(t, observedLogs.All(), 1, i)
			fields, ok := observedLogs.All()[0].ContextMap()["query"].(map[string]interface{})
			require.True(t, ok, i)
			require.Equal(t, "[...]", fields[test.query], i)
		}
	}
}

func TestConfidentalJSONFields(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	tests := []struct {
		header string
		query  string
	}{
		{query: xhttp.AmzAccessKeyID, header: ""},
		{query: xhttp.AmzSignatureV2, header: ""},
		{query: xhttp.AmzSignature, header: ""},
		{query: xhttp.AmzCredential, header: ""},
		{query: "prefix", header: ""},
		{header: xhttp.Authorization, query: ""},
		{header: "Cookie", query: ""},
		{header: xhttp.AmzCopySource, query: ""},
		{query: "delimiter", header: ""},
	}
	for i, test := range tests {
		var b []byte
		var err error
		var key string
		switch {
		case test.header != "":
			key = test.header
			b, err = json.Marshal(&HeadersLogObject{Headers: http.Header{key: []string{"value"}}})
		case test.query != "":
			key = test.query
			b, err = json.Marshal(&RequestQueryLogObject{Query: url.Values{key: []string{"value"}}})
		default:
			t.Error("misconfigured test")
		}

		require.NoError(t, err)
		result := make(map[string]string)
		require.NoError(t, json.Unmarshal(b, &result), i)
		require.Equal(t, "[...]", result[key], i)
	}
}
