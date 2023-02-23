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
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"storj.io/common/grant"
	"storj.io/common/macaroon"
	"storj.io/common/memory"
	"storj.io/common/storj"
	"storj.io/common/testcontext"
	"storj.io/gateway-mt/pkg/auth/authdb"
	"storj.io/gateway-mt/pkg/auth/badgerauth"
	"storj.io/gateway-mt/pkg/auth/badgerauth/pb"
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

		res := New(zaptest.NewLogger(t), nil, endpoint, []string{"authToken"}, 4*memory.KiB)
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
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	logger := zaptest.NewLogger(t)
	defer ctx.Check(logger.Sync)

	kv := newKV(t, logger)
	defer ctx.Check(kv.Close)

	endpoint, err := url.Parse("http://endpoint.invalid/")
	require.NoError(t, err)

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

	t.Run("Availability after startup", func(t *testing.T) {
		allowed := map[storj.NodeURL]struct{}{minimalAccessSatelliteID: {}}
		res := newResource(t, logger, authdb.NewDatabase(kv, allowed), endpoint)

		const path = "/v1/health/startup"

		_, ok := exec(res, "GET", path, "")
		require.False(t, ok)
		_, ok = exec(res, "GET", "/v1/health/live", "")
		require.False(t, ok)

		res.SetStartupDone()

		_, ok = exec(res, "GET", "/v1/health/live", "")
		require.True(t, ok)
		_, ok = exec(res, "GET", path, "")
		require.True(t, ok)
	})

	t.Run("CRUD", func(t *testing.T) {
		allowed := map[storj.NodeURL]struct{}{minimalAccessSatelliteID: {}}
		res := newResource(t, logger, authdb.NewDatabase(kv, allowed), endpoint)

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
		res := newResource(t, logger, authdb.NewDatabase(kv, allowed), endpoint)

		// create an access
		createRequest := fmt.Sprintf(`{"access_grant": %q}`, minimalAccess)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/v1/access", strings.NewReader(createRequest))
		req.Header.Set("Authorization", "Bearer authToken")
		res.ServeHTTP(rec, req)
		require.Equal(t, http.StatusBadRequest, rec.Code)

		_, ok := exec(res, "POST", "/v1/access", createRequest)
		require.False(t, ok)

		allowed = map[storj.NodeURL]struct{}{unknownSatelliteID: {}, minimalAccessSatelliteID: {}}
		res = newResource(t, logger, authdb.NewDatabase(kv, allowed), endpoint)

		// create an access
		createRequest = fmt.Sprintf(`{"access_grant": %q}`, minimalAccess)
		_, ok = exec(res, "POST", "/v1/access", createRequest)
		require.True(t, ok)

		allowed, _, err := satellitelist.LoadSatelliteURLs(context.Background(), []string{"12EayRS2V1kEsWESU9QMRseFhdxYxKicsiFmxrsLZHeLUtdps3S@us-central-1.tardigrade.io:7777"})
		require.NoError(t, err)
		res = newResource(t, logger, authdb.NewDatabase(kv, allowed), endpoint)
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
		res := newResource(t, logger, authdb.NewDatabase(kv, allowed), endpoint)

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

	t.Run("Invalidated", func(t *testing.T) {
		allowed := map[storj.NodeURL]struct{}{minimalAccessSatelliteID: {}}
		res := newResource(t, logger, authdb.NewDatabase(kv, allowed), endpoint)

		createRequest := fmt.Sprintf(`{"access_grant": %q, "public": true}`, minimalAccess)
		createResult, ok := exec(res, "POST", "/v1/access", createRequest)
		require.True(t, ok)

		var key authdb.EncryptionKey
		require.NoError(t, key.FromBase32(createResult["access_key_id"].(string)))

		admin := badgerauth.NewAdmin(kv.(*badgerauth.Node).UnderlyingDB())
		_, err := admin.InvalidateRecord(ctx, &pb.InvalidateRecordRequest{Key: key.Hash().Bytes(), Reason: "takedown"})
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", fmt.Sprintf("/v1/access/%s", createResult["access_key_id"]), nil)
		req.Header.Set("Authorization", "Bearer authToken")
		res.ServeHTTP(rec, req)

		require.Equal(t, http.StatusUnauthorized, rec.Code)
		require.Contains(t, rec.Body.String(), "takedown")
	})

	t.Run("Invalid request", func(t *testing.T) {
		allowed := map[storj.NodeURL]struct{}{minimalAccessSatelliteID: {}}
		res := newResource(t, logger, authdb.NewDatabase(kv, allowed), endpoint)

		check := func(body string, expectedCode int) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/v1/access", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer authToken")
			res.ServeHTTP(rec, req)

			require.Equal(t, expectedCode, rec.Code, fmt.Sprintf("body: %s", body))
		}

		check("", http.StatusUnprocessableEntity)
		check("lol", http.StatusUnprocessableEntity)
		check("{}", http.StatusBadRequest)
		check(`{"public": true}`, http.StatusBadRequest)
		check(`{"access_grant": "ABC123", "public": true}`, http.StatusBadRequest)
	})
}

func TestResources_Authorization(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	logger := zaptest.NewLogger(t)
	defer ctx.Check(logger.Sync)

	kv := newKV(t, logger)
	defer ctx.Check(kv.Close)

	endpoint, err := url.Parse("http://endpoint.invalid/")
	require.NoError(t, err)

	allowed := map[storj.NodeURL]struct{}{minimalAccessSatelliteID: {}}
	res := newResource(t, logger, authdb.NewDatabase(kv, allowed), endpoint)

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

	// Test multiple auth tokens
	checkAuth := func(method, path, authToken string, resultCase bool) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Authorization", "Bearer "+authToken)
		res.ServeHTTP(rec, req)
		if resultCase {
			require.Equal(t, http.StatusOK, rec.Code)
		} else {
			require.Equal(t, http.StatusUnauthorized, rec.Code)
		}
	}

	// Correct token should work, new one should not
	checkAuth("GET", baseURL, "authToken", true)
	checkAuth("GET", baseURL, "newAuthToken", false)

	// Setting both token to be valid
	res.authToken = []string{"authToken", "newAuthToken"}
	// Both token should work now
	checkAuth("GET", baseURL, "authToken", true)
	checkAuth("GET", baseURL, "newAuthToken", true)

	// Removing old token
	res.authToken = []string{"newAuthToken"}
	// Only new token should continue to work
	checkAuth("GET", baseURL, "authToken", false)
	checkAuth("GET", baseURL, "newAuthToken", true)

	// Unsetting the token list, should allow all requests
	res.authToken = []string{}
	// Only new token should continue to work
	checkAuth("GET", baseURL, "authToken", true)
	checkAuth("GET", baseURL, "newAuthToken", true)
	checkAuth("GET", baseURL, "hacktheplanet", true)
}

func TestResources_CORS(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	logger := zaptest.NewLogger(t)
	defer ctx.Check(logger.Sync)

	endpoint, err := url.Parse("http://endpoint.invalid/")
	require.NoError(t, err)

	check := func(method, path string) bool {
		rec := httptest.NewRecorder()

		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Authorization", "Bearer authToken")
		req.Header.Add("Origin", "http://example.com")

		res := newResource(t, logger, nil, endpoint)
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

func TestResources_Shutdown(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	logger := zaptest.NewLogger(t)
	defer ctx.Check(logger.Sync)

	kv := newKV(t, logger)
	defer ctx.Check(kv.Close)

	endpoint, err := url.Parse("http://endpoint.test/")
	require.NoError(t, err)

	check := func(inShutdown bool) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/v1/health/live", nil)

		allowed := map[storj.NodeURL]struct{}{minimalAccessSatelliteID: {}}
		res := newResource(t, logger, authdb.NewDatabase(kv, allowed), endpoint)
		res.SetStartupDone()
		if inShutdown {
			res.SetShutdown()
		}
		res.ServeHTTP(rec, req)

		result := rec.Result()
		require.NoError(t, result.Body.Close())

		return rec.Code
	}

	assert.Equal(t, http.StatusOK, check(false))
	assert.Equal(t, http.StatusServiceUnavailable, check(true))
}

func TestResources_EntityTooLarge(t *testing.T) {
	const path = "/v1/access"

	res := New(zaptest.NewLogger(t), nil, nil, []string{""}, 1)

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

func newResource(t *testing.T, logger *zap.Logger, db *authdb.Database, endpoint *url.URL) *Resources {
	t.Helper()

	return New(logger, db, endpoint, []string{"authToken"}, 4*memory.KiB)
}

func newKV(t *testing.T, logger *zap.Logger) (_ authdb.KV) {
	t.Helper()

	kv, err := badgerauth.New(logger, badgerauth.Config{FirstStart: true})
	require.NoError(t, err)

	return kv
}
