// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package httpcoding_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"storj.io/edge/pkg/httpcoding"
)

func TestIsAcceptable(t *testing.T) {
	require.True(t, httpcoding.IsAcceptable(httpcoding.Gzip, http.Header{}))
	require.True(t, httpcoding.IsAcceptable(httpcoding.Identity, http.Header{"Accept-Encoding": []string{""}}))

	for _, tt := range []struct {
		value    string
		accepted bool
	}{
		{"gzip", true},
		{"gzip, br", true},
		{"", false},
		{"*", true},
		{"*;q=0", false},
		{"*;q=0.1", true},
		{"gzip;q=0", false},
		{"gzip;q=0.1", true},
		{" GzIp ; Q = 0.1 ,", true},
		{"gzip, *;q=0", true},
		{"identity", false},
		{"deflate, br", false},
	} {
		header := http.Header{"Accept-Encoding": []string{tt.value}}
		require.Equal(t, tt.accepted, httpcoding.IsAcceptable(httpcoding.Gzip, header), "Header value: %s", tt.value)
	}

	for _, tt := range []struct {
		value    string
		accepted bool
	}{
		{"gzip", true},
		{"identity", true},
		{"identity;q=0", false},
		{"gzip, *;q=0", false},
		{"gzip, identity;q=0", false},
	} {
		header := http.Header{"Accept-Encoding": []string{tt.value}}
		require.Equal(t, tt.accepted, httpcoding.IsAcceptable(httpcoding.Identity, header), "Header value: %s", tt.value)
	}
}

func TestIsAcceptableWildcardPanics(t *testing.T) {
	require.Panics(t, func() {
		httpcoding.IsAcceptable("*", http.Header{})
	})
}
