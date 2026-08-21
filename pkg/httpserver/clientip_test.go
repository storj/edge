// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package httpserver

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClientIP(t *testing.T) {
	testCases := []struct {
		desc       string
		remoteAddr string
		header     http.Header
		expectedIP string
	}{
		{
			desc:       "RemoteAddr only (IPv4, no port)",
			remoteAddr: "1.2.3.4",
			expectedIP: "1.2.3.4",
		},
		{
			desc:       "RemoteAddr only (IPv4 with port)",
			remoteAddr: "1.2.3.4:5678",
			expectedIP: "1.2.3.4",
		},
		{
			desc:       "RemoteAddr only (IPv6, no port)",
			remoteAddr: "2001:db8::1",
			expectedIP: "2001:db8::1",
		},
		{
			desc:       "RemoteAddr only (IPv6 with port)",
			remoteAddr: "[2001:db8::1]:5678",
			expectedIP: "2001:db8::1",
		},
		{
			desc:       "X-Real-Ip beats RemoteAddr",
			remoteAddr: "1.2.3.4",
			header:     http.Header{"X-Real-Ip": []string{"4.5.6.7"}},
			expectedIP: "4.5.6.7",
		},
		{
			desc:       "X-Forwarded-For single entry beats RemoteAddr",
			remoteAddr: "1.2.3.4",
			header:     http.Header{"X-Forwarded-For": []string{"4.5.6.7"}},
			expectedIP: "4.5.6.7",
		},
		{
			desc:       "X-Forwarded-For takes the last entry",
			remoteAddr: "1.2.3.4",
			header:     http.Header{"X-Forwarded-For": []string{"172.28.254.80, 192.168.80.25"}},
			expectedIP: "192.168.80.25",
		},
		{
			desc:       "X-Forwarded-For beats X-Real-Ip",
			remoteAddr: "1.2.3.4",
			header: http.Header{
				"X-Forwarded-For": []string{"4.5.6.7"},
				"X-Real-Ip":       []string{"7.8.9.0"},
			},
			expectedIP: "4.5.6.7",
		},
		{
			desc:       "Forwarded with single for=IPv4",
			remoteAddr: "1.2.3.4",
			header:     http.Header{"Forwarded": []string{"for=4.3.2.1"}},
			expectedIP: "4.3.2.1",
		},
		{
			desc:       "Forwarded with for= and other directives",
			remoteAddr: "1.2.3.4",
			header:     http.Header{"Forwarded": []string{"for=4.3.2.1;proto=http;by=203.0.113.43"}},
			expectedIP: "4.3.2.1",
		},
		{
			desc:       "Forwarded takes the last for= entry",
			remoteAddr: "1.2.3.4",
			header:     http.Header{"Forwarded": []string{"for=192.0.2.43, for=198.51.100.17"}},
			expectedIP: "198.51.100.17",
		},
		{
			desc:       "Forwarded with quoted IPv4 and port",
			remoteAddr: "1.2.3.4",
			header:     http.Header{"Forwarded": []string{`for="192.0.2.43:8080"`}},
			expectedIP: "192.0.2.43",
		},
		{
			desc:       "Forwarded with quoted bracketed IPv6",
			remoteAddr: "1.2.3.4",
			header:     http.Header{"Forwarded": []string{`for="[2001:db8::1]"`}},
			expectedIP: "2001:db8::1",
		},
		{
			desc:       "Forwarded with quoted bracketed IPv6 and port",
			remoteAddr: "1.2.3.4",
			header:     http.Header{"Forwarded": []string{`for="[2001:db8::1]:4711"`}},
			expectedIP: "2001:db8::1",
		},
		{
			desc:       "Forwarded with case-insensitive directive key",
			remoteAddr: "1.2.3.4",
			header:     http.Header{"Forwarded": []string{"FOR=4.3.2.1"}},
			expectedIP: "4.3.2.1",
		},
		{
			desc:       "Forwarded beats X-Forwarded-For and X-Real-Ip",
			remoteAddr: "1.2.3.4",
			header: http.Header{
				"Forwarded":       []string{"for=4.3.2.1"},
				"X-Forwarded-For": []string{"4.5.6.7"},
				"X-Real-Ip":       []string{"7.8.9.0"},
			},
			expectedIP: "4.3.2.1",
		},
		{
			desc:       "Forwarded without for= falls through to next header",
			remoteAddr: "1.2.3.4",
			header: http.Header{
				"Forwarded":       []string{"proto=http;by=203.0.113.43"},
				"X-Forwarded-For": []string{"4.5.6.7"},
			},
			expectedIP: "4.5.6.7",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			r := &http.Request{
				RemoteAddr: tc.remoteAddr,
				Header:     tc.header,
			}
			require.Equal(t, tc.expectedIP, ClientIP(r))
		})
	}
}
