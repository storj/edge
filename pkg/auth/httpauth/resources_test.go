// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package httpauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/grant"
	"storj.io/common/macaroon"
	"storj.io/common/memory"
	"storj.io/common/storj"
	"storj.io/gateway-mt/pkg/auth/authdb"
	"storj.io/gateway-mt/pkg/auth/memauth"
	"storj.io/gateway-mt/pkg/auth/satellitelist"
)

const minimalAccess = "13J4Upun87ATb3T5T5sDXVeQaCzWFZeF9Ly4ELfxS5hUwTL8APEkwahTEJ1wxZjyErimiDs3kgid33kDLuYPYtwaY7Toy32mCTapfrUB814X13RiA844HPWK3QLKZb9cAoVceTowmNZXWbcUMKNbkMHCURE4hn8ZrdHPE3S86yngjvDxwKmarfGx"

// This is the satellite address embedded in the access above.
const minimalAccessSatelliteURL = "1SYXsAycDPUu4z2ZksJD5fh5nTDcH3vCFHnpcVye5XuL1NrYV@s"

var minimalAccessSatelliteID = func() storj.NodeURL {
	url, err := storj.ParseNodeURL(minimalAccessSatelliteURL)
	if err != nil {
		panic(err)
	}
	return url
}()

func TestResources_URLs(t *testing.T) {
	endpoint, err := url.Parse("http://endpoint.invalid/")
	require.NoError(t, err)

	check := func(method, path string) bool {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Authorization", "Bearer authToken")

		res := New(zaptest.NewLogger(t), nil, endpoint, "authToken", 4*memory.KiB)
		res.ServeHTTP(rec, req)
		return rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed
	}

	// check valid paths
	require.True(t, check("POST", "/v1/access"))
	require.True(t, check("GET", "/v1/access/someid"))

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

	// check trailing slashes are invalid
	require.False(t, check("POST", "/v1/access/"))
	require.False(t, check("GET", "/v1/access/someid/"))
	require.False(t, check("PUT", "/v1/access/someid/invalid/"))
	require.False(t, check("DELETE", "/v1/access/someid/"))
}

func TestResources_CRUD(t *testing.T) {
	exec := func(res http.Handler, method, path, body string) (map[string]interface{}, bool) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer authToken")
		res.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			return nil, false
		}
		if rec.Header().Get("Content-Type") == "application/json" {
			var out map[string]interface{}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
			return out, true
		}
		return nil, true
	}

	endpoint, err := url.Parse("http://endpoint.invalid/")
	require.NoError(t, err)

	t.Run("Availability after startup", func(t *testing.T) {
		allowed := map[storj.NodeURL]struct{}{minimalAccessSatelliteID: {}}
		res := newResource(t, authdb.NewDatabase(memauth.New(), allowed), endpoint)

		const path = "/v1/health/startup"

		_, ok := exec(res, "GET", path, "")
		require.False(t, ok)
		_, ok = exec(res, "GET", "/v1/health/live", "")
		require.False(t, ok)

		res.SetStartupDone()

		_, ok = exec(res, "GET", path, "")
		require.True(t, ok)
	})

	t.Run("CRUD", func(t *testing.T) {
		allowed := map[storj.NodeURL]struct{}{minimalAccessSatelliteID: {}}
		res := newResource(t, authdb.NewDatabase(memauth.New(), allowed), endpoint)

		// create an access
		createRequest := fmt.Sprintf(`{"access_grant": %q}`, minimalAccess)
		createResult, ok := exec(res, "POST", "/v1/access", createRequest)
		require.True(t, ok)
		require.Equal(t, createResult["endpoint"], endpoint.String())
		url := fmt.Sprintf("/v1/access/%s", createResult["access_key_id"])

		// retrieve an access
		fetchResult, ok := exec(res, "GET", url, ``)
		require.True(t, ok)
		require.Equal(t, minimalAccess, fetchResult["access_grant"])
		require.Equal(t, createResult["secret_key"], fetchResult["secret_key"])
	})

	t.Run("ApprovedSatelliteID", func(t *testing.T) {
		var unknownSatelliteID storj.NodeURL
		unknownSatelliteID.ID[4] = 7
		allowed := map[storj.NodeURL]struct{}{unknownSatelliteID: {}}
		res := newResource(t, authdb.NewDatabase(memauth.New(), allowed), endpoint)

		// create an access
		createRequest := fmt.Sprintf(`{"access_grant": %q}`, minimalAccess)
		_, ok := exec(res, "POST", "/v1/access", createRequest)
		require.False(t, ok)

		allowed = map[storj.NodeURL]struct{}{unknownSatelliteID: {}, minimalAccessSatelliteID: {}}
		res = newResource(t, authdb.NewDatabase(memauth.New(), allowed), endpoint)

		// create an access
		createRequest = fmt.Sprintf(`{"access_grant": %q}`, minimalAccess)
		_, ok = exec(res, "POST", "/v1/access", createRequest)
		require.True(t, ok)

		allowed, _, err := satellitelist.LoadSatelliteURLs(context.Background(), []string{"12EayRS2V1kEsWESU9QMRseFhdxYxKicsiFmxrsLZHeLUtdps3S@us-central-1.tardigrade.io:7777"})
		require.NoError(t, err)
		res = newResource(t, authdb.NewDatabase(memauth.New(), allowed), endpoint)
		mac, err := macaroon.NewAPIKey(nil)
		require.NoError(t, err)
		access := grant.Access{
			SatelliteAddress: "us-central-1.tardigrade.io:7777",
			APIKey:           mac,
			EncAccess:        grant.NewEncryptionAccess(),
		}

		noNodeID, err := access.Serialize()
		require.NoError(t, err)

		// create an access
		createRequest = fmt.Sprintf(`{"access_grant": %q}`, noNodeID)
		_, ok = exec(res, "POST", "/v1/access", createRequest)
		require.True(t, ok)
	})

	t.Run("Public", func(t *testing.T) {
		allowed := map[storj.NodeURL]struct{}{minimalAccessSatelliteID: {}}
		res := newResource(t, authdb.NewDatabase(memauth.New(), allowed), endpoint)

		// create a public access
		createRequest := fmt.Sprintf(`{"access_grant": %q, "public": true}`, minimalAccess)
		createResult, ok := exec(res, "POST", "/v1/access", createRequest)
		require.True(t, ok)
		require.Equal(t, createResult["endpoint"], endpoint.String())
		url := fmt.Sprintf("/v1/access/%s", createResult["access_key_id"])

		// retrieve an access
		fetchResult, ok := exec(res, "GET", url, ``)
		require.True(t, ok)
		require.Equal(t, minimalAccess, fetchResult["access_grant"])
		require.True(t, fetchResult["public"].(bool))
	})
}

func TestResources_Authorization(t *testing.T) {
	endpoint, err := url.Parse("http://endpoint.invalid/")
	require.NoError(t, err)

	allowed := map[storj.NodeURL]struct{}{minimalAccessSatelliteID: {}}
	res := newResource(t, authdb.NewDatabase(memauth.New(), allowed), endpoint)

	// create an access grant and base url
	createRequest := fmt.Sprintf(`{"access_grant": %q}`, minimalAccess)
	req := httptest.NewRequest("POST", "/v1/access", strings.NewReader(createRequest))
	rec := httptest.NewRecorder()
	res.ServeHTTP(rec, req)
	var out map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	baseURL := fmt.Sprintf("/v1/access/%s", out["access_key_id"])

	check := func(method, path string) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, nil)
		res.ServeHTTP(rec, req)
		require.Equal(t, http.StatusUnauthorized, rec.Code)
	}

	// check that these requests are unauthorized
	check("GET", baseURL)
}

func TestResources_CORS(t *testing.T) {
	endpoint, err := url.Parse("http://endpoint.invalid/")
	require.NoError(t, err)

	check := func(method, path string) bool {
		rec := httptest.NewRecorder()

		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Authorization", "Bearer authToken")
		req.Header.Add("Origin", "http://example.com")

		res := newResource(t, nil, endpoint)
		res.ServeHTTP(rec, req)

		result := rec.Result()
		require.NoError(t, result.Body.Close())

		respHeaders := result.Header.Get("Access-Control-Allow-Origin")
		if respHeaders != "*" {
			return false
		}
		respHeaders = result.Header.Get("Access-Control-Allow-Methods")
		if respHeaders != "POST, OPTIONS" {
			return false
		}
		respHeaders = result.Header.Get("Access-Control-Allow-Headers")
		return respHeaders == "Content-Type, Accept, Accept-Language, Content-Language, Content-Length, Accept-Encoding"
	}

	require.True(t, check("POST", "/v1/access"))
	require.True(t, check("OPTIONS", "/v1/access"))
	require.False(t, check("GET", "/v1/access/someid"))
	require.False(t, check("PUT", "/v1/access/someid/invalid"))
	require.False(t, check("DELETE", "/v1/access/someid"))
}

func TestResources_EntityTooLarge(t *testing.T) {
	const path = "/v1/access"

	res := New(zaptest.NewLogger(t), nil, nil, "", 1)

	body := strings.NewReader("{}")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, body)
	res.ServeHTTP(rec, req)

	r := rec.Result()
	require.NoError(t, r.Body.Close())
	assert.Equal(t, http.StatusRequestEntityTooLarge, r.StatusCode)

	// Make sure we reject lying requests:

	body.Reset("{}")

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, path, body)
	req.ContentLength = 1
	res.ServeHTTP(rec, req)

	r = rec.Result()
	require.NoError(t, r.Body.Close())
	assert.Equal(t, http.StatusRequestEntityTooLarge, r.StatusCode)

	// Make sure we do our best to differentiate between unexpected EOF that
	// Decode returns when we cut reads for safety and when the JSON is broken
	// itself:

	body.Reset("{")

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, path, body)
	res.ServeHTTP(rec, req)

	r = rec.Result()
	require.NoError(t, r.Body.Close())
	assert.Equal(t, http.StatusUnprocessableEntity, r.StatusCode)
}

func newResource(t *testing.T, db *authdb.Database, endpoint *url.URL) *Resources {
	t.Helper()

	return New(zaptest.NewLogger(t), db, endpoint, "authToken", 4*memory.KiB)
}
