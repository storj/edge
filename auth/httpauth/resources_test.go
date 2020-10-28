// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package httpauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"storj.io/stargate/auth"
	"storj.io/stargate/auth/memauth"
)

const minimalAccess = "138CV9Drxrw8ir1XpxcZhk2wnHjhzVjuSZe6yDsNiMZDP8cow9V6sHDYdwgvYoQGgqVvoMnxdWDbpBiEPW5oP7DtPJ5sZx2MVxFrUoZYFfVAgxidW"

func TestResources_URLs(t *testing.T) {
	check := func(method, path string) bool {
		rec := httptest.NewRecorder()
		New(nil).ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		return rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed
	}

	// check valid paths
	require.True(t, check("POST", "/v1/access"))
	require.True(t, check("GET", "/v1/access/someid"))
	require.True(t, check("PUT", "/v1/access/someid/invalid"))
	require.True(t, check("DELETE", "/v1/access/someid"))

	// check invalid methods
	require.False(t, check("PATCH", "/v1/access"))
	require.False(t, check("PATCH", "/v1/access/someid"))
	require.False(t, check("PATCH", "/v1/access/someid/invalid"))

	// check suffix doesn't match
	require.False(t, check("POST", "/v1/access/extra"))
	require.False(t, check("GET", "/v1/access/someid/extra"))
	require.False(t, check("PUT", "/v1/access/someid/invalid/extra"))
	require.False(t, check("DELETE", "/v1/access/someid/extra"))

	// check misspelling doesn't match
	require.False(t, check("POST", "/v1/access_"))
	require.False(t, check("GET", "/v1/access_/someid"))
	require.False(t, check("DELETE", "/v1/access_/someid"))
	require.False(t, check("PUT", "/v1/access_/someid/invalid"))
	require.False(t, check("PUT", "/v1/access/someid/invalid_"))
}

func TestResources_CRUD(t *testing.T) {
	f := fmt.Sprintf
	res := New(auth.NewDatabase(memauth.New()))

	exec := func(method, path, body string) map[string]interface{} {
		rec := httptest.NewRecorder()
		res.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		t.Log("response body:", rec.Body.String())
		require.Equal(t, rec.Code, http.StatusOK)
		out := make(map[string]interface{})
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
		return out
	}

	// create an access
	createResult := exec("POST", "/v1/access", f(`{"access_grant": %q}`, minimalAccess))

	// retrieve an access
	fetchResult := exec("GET", fmt.Sprintf("/v1/access/%s", createResult["access_key_id"]), ``)
	require.Equal(t, minimalAccess, fetchResult["access_grant"])
}
