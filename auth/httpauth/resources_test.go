// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package httpauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResources_URLs(t *testing.T) {
	res := New(nil)
	matches := func(method, path string) bool {
		rec := httptest.NewRecorder()
		res.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		return rec.Code == http.StatusInternalServerError // TODO: change when implemented
	}

	// check valid paths
	require.True(t, matches("POST", "/v1/access"))
	require.True(t, matches("GET", "/v1/access/someid"))
	require.True(t, matches("DELETE", "/v1/access/someid"))
	require.True(t, matches("PUT", "/v1/access/someid/invalid"))

	// check invalid methods
	require.False(t, matches("PATCH", "/v1/access"))
	require.False(t, matches("PATCH", "/v1/access/someid"))
	require.False(t, matches("PATCH", "/v1/access/someid"))
	require.False(t, matches("PATCH", "/v1/access/someid/invalid"))

	// check suffix doesn't match
	require.False(t, matches("POST", "/v1/access/extra"))
	require.False(t, matches("GET", "/v1/access/someid/extra"))
	require.False(t, matches("DELETE", "/v1/access/someid/extra"))
	require.False(t, matches("PUT", "/v1/access/someid/invalid/extra"))

	// check misspelling doesn't match
	require.False(t, matches("POST", "/v1/access_"))
	require.False(t, matches("GET", "/v1/access_/someid"))
	require.False(t, matches("DELETE", "/v1/access_/someid"))
	require.False(t, matches("PUT", "/v1/access_/someid/invalid"))
	require.False(t, matches("PUT", "/v1/access/someid/invalid_"))
}
