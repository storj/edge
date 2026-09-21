// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestRemoteIP(t *testing.T) {
	testCases := []struct {
		desc       string
		remoteAddr string
		header     http.Header
		expectedIP string
	}{
		{
			desc:       "RemoteAddr only",
			remoteAddr: "1.2.3.4",
			expectedIP: "1.2.3.4",
		},
		{
			desc:       "X-Forwarded-For, and RemoteAddr",
			remoteAddr: "1.2.3.4",
			header:     http.Header{"X-Forwarded-For": []string{"4.5.6.7"}},
			expectedIP: "4.5.6.7",
		},
		{
			desc:       "X-Real-Ip, and RemoteAddr",
			remoteAddr: "1.2.3.4",
			header:     http.Header{"X-Real-Ip": []string{"4.5.6.7"}},
			expectedIP: "4.5.6.7",
		},
		{
			desc:       "Forwarded, and RemoteAddr",
			remoteAddr: "1.2.3.4",
			header:     http.Header{"Forwarded": []string{"for=7.8.9.0"}},
			expectedIP: "7.8.9.0",
		},
		{
			desc:       "X-Forwarded-For, X-Real-Ip, and RemoteAddr",
			remoteAddr: "1.2.3.4",
			header: http.Header{
				"X-Forwarded-For": []string{"4.5.6.7"},
				"X-Real-Ip":       []string{"7.8.9.0"},
			},
			expectedIP: "4.5.6.7",
		},
		{
			desc:       "Forwarded, X-Forwarded-For, X-Real-Ip, and RemoteAddr",
			remoteAddr: "1.2.3.4",
			header: http.Header{
				"Forwarded":       []string{"for=4.3.2.1"},
				"X-Forwarded-For": []string{"4.5.6.7"},
				"X-Real-Ip":       []string{"7.8.9.0"},
			},
			expectedIP: "4.3.2.1",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			handler := func() http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				})
			}

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			req.RemoteAddr = tc.remoteAddr
			req.Header = tc.header

			rr := httptest.NewRecorder()

			observedZapCore, observedLogs := observer.New(zap.DebugLevel)
			observedLogger := zap.New(observedZapCore)

			logResponses(observedLogger, handler()).ServeHTTP(rr, req)

			require.Len(t, observedLogs.All(), 1)
			fields, ok := observedLogs.All()[0].ContextMap()["http_request"].(map[string]any)
			require.True(t, ok)

			require.Equal(t, tc.expectedIP, fields["remoteIp"])
		})
	}
}

func TestServerErrorLog(t *testing.T) {
	for _, tc := range []struct {
		msg   string
		level zapcore.Level
	}{
		{
			msg:   "http: TLS handshake error from 1.2.3.4:65049: EOF",
			level: zap.DebugLevel,
		},
		{
			msg:   "http: superfluous response.WriteHeader call",
			level: zap.InfoLevel,
		},
	} {
		t.Run(tc.msg, func(t *testing.T) {
			observedZapCore, observedLogs := observer.New(zap.DebugLevel)

			newServerErrorLog(zap.New(observedZapCore)).Print(tc.msg)

			require.Len(t, observedLogs.All(), 1)
			require.Equal(t, tc.msg, observedLogs.All()[0].Message)
			require.Equal(t, tc.level, observedLogs.All()[0].Level)
		})
	}
}
