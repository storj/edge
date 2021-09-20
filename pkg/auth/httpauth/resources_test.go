// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package httpauth

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/grant"
	"storj.io/common/macaroon"
	"storj.io/common/storj"
	"storj.io/common/testcontext"
	"storj.io/common/testrand"
	"storj.io/gateway-mt/pkg/auth/authdb"
	"storj.io/gateway-mt/pkg/auth/failrate"
	"storj.io/gateway-mt/pkg/auth/memauth"
	"storj.io/gateway-mt/pkg/auth/satellitelist"
)

const minimalAccess = "13J4Upun87ATb3T5T5sDXVeQaCzWFZeF9Ly4ELfxS5hUwTL8APEkwahTEJ1wxZjyErimiDs3kgid33kDLuYPYtwaY7Toy32mCTapfrUB814X13RiA844HPWK3QLKZb9cAoVceTowmNZXWbcUMKNbkMHCURE4hn8ZrdHPE3S86yngjvDxwKmarfGx"

// This is the satellite address embedded in the access above.
const minimalAccessSatelliteURL = "1SYXsAycDPUu4z2ZksJD5fh5nTDcH3vCFHnpcVye5XuL1NrYV@s"

var minimalAccessSatelliteID = func() storj.NodeID {
	url, err := storj.ParseNodeURL(minimalAccessSatelliteURL)
	if err != nil {
		panic(err)
	}
	return url.ID
}()

func TestResources_URLs(t *testing.T) {
	endpoint, err := url.Parse("http://endpoint.invalid/")
	require.NoError(t, err)

	check := func(method, path string) bool {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Authorization", "Bearer authToken")

		limiters, err := failrate.NewLimiters(failrate.LimitersConfig{
			MaxReqsSecond: 1,
			Burst:         1,
			NumLimits:     10,
		})
		require.NoError(t, err)

		res := New(zaptest.NewLogger(t), nil, endpoint, "authToken", limiters)
		res.ServeHTTP(rec, req)
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
		allowed := map[storj.NodeID]struct{}{minimalAccessSatelliteID: {}}
		res := newResource(t, authdb.NewDatabase(memauth.New(), allowed), endpoint, nil)

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
		allowed := map[storj.NodeID]struct{}{minimalAccessSatelliteID: {}}
		res := newResource(t, authdb.NewDatabase(memauth.New(), allowed), endpoint, nil)

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

		// delete an access
		deleteResult, ok := exec(res, "DELETE", url, ``)
		require.True(t, ok)
		require.Equal(t, map[string]interface{}{}, deleteResult)

		// retrieve fails now
		_, ok = exec(res, "GET", url, ``)
		require.False(t, ok)
	})

	t.Run("ApprovedSatelliteID", func(t *testing.T) {
		var unknownSatelliteID storj.NodeID
		unknownSatelliteID[4] = 7
		allowed := map[storj.NodeID]struct{}{unknownSatelliteID: {}}
		res := newResource(t, authdb.NewDatabase(memauth.New(), allowed), endpoint, nil)

		// create an access
		createRequest := fmt.Sprintf(`{"access_grant": %q}`, minimalAccess)
		_, ok := exec(res, "POST", "/v1/access", createRequest)
		require.False(t, ok)

		allowed = map[storj.NodeID]struct{}{unknownSatelliteID: {}, minimalAccessSatelliteID: {}}
		res = newResource(t, authdb.NewDatabase(memauth.New(), allowed), endpoint, nil)

		// create an access
		createRequest = fmt.Sprintf(`{"access_grant": %q}`, minimalAccess)
		_, ok = exec(res, "POST", "/v1/access", createRequest)
		require.True(t, ok)

		allowed, _, err := satellitelist.LoadSatelliteIDs(context.Background(), []string{"12EayRS2V1kEsWESU9QMRseFhdxYxKicsiFmxrsLZHeLUtdps3S@us-central-1.tardigrade.io:7777"})
		require.NoError(t, err)
		res = newResource(t, authdb.NewDatabase(memauth.New(), allowed), endpoint, nil)
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

	t.Run("Invalidate", func(t *testing.T) {
		allowed := map[storj.NodeID]struct{}{minimalAccessSatelliteID: {}}
		res := newResource(t, authdb.NewDatabase(memauth.New(), allowed), endpoint, nil)

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

		// invalidate an access
		invalidateResult, ok := exec(res, "PUT", url+"/invalid", `{"reason": "test"}`)
		require.True(t, ok)
		require.Equal(t, map[string]interface{}{}, invalidateResult)

		// retrieve fails now
		_, ok = exec(res, "GET", url, ``)
		require.False(t, ok)
	})

	t.Run("Public", func(t *testing.T) {
		allowed := map[storj.NodeID]struct{}{minimalAccessSatelliteID: {}}
		res := newResource(t, authdb.NewDatabase(memauth.New(), allowed), endpoint, nil)

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

	allowed := map[storj.NodeID]struct{}{minimalAccessSatelliteID: {}}
	res := newResource(t, authdb.NewDatabase(memauth.New(), allowed), endpoint, nil)

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
	check("PUT", baseURL+"/invalid")
	check("DELETE", baseURL)
}

func TestResources_CORS(t *testing.T) {
	endpoint, err := url.Parse("http://endpoint.invalid/")
	require.NoError(t, err)

	check := func(method, path string) bool {
		rec := httptest.NewRecorder()

		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Authorization", "Bearer authToken")
		req.Header.Add("Origin", "http://example.com")

		res := newResource(t, nil, endpoint, nil)
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

func TestResources_getAccess_withLimiters(t *testing.T) {
	endpoint, err := url.Parse("http://endpoint.invalid/")
	require.NoError(t, err)
	allowed := map[storj.NodeID]struct{}{minimalAccessSatelliteID: {}}

	limiters, err := failrate.NewLimiters(failrate.LimitersConfig{
		MaxReqsSecond: 1, Burst: 1, NumLimits: 10,
	})
	require.NoError(t, err)
	res := newResource(
		t, authdb.NewDatabase(memauth.New(), allowed), endpoint, limiters,
	)

	accessKeyID := createAccess(t, minimalAccess, res)

	t.Run("allowed", func(t *testing.T) {
		ctx := testcontext.New(t)
		defer ctx.Cleanup()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "/v1/access/"+accessKeyID, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer authToken")
		rc := httptest.NewRecorder()
		res.ServeHTTP(rc, req)
		require.Equal(t, http.StatusOK, rc.Code)
	})

	t.Run("rate-limited", func(t *testing.T) {
		ctx := testcontext.New(t)
		defer ctx.Cleanup()

		deletedAccess := createAccess(t, generateAccessGrant(t, time.Time{}), res)

		// Delete the access grant for being able to request one that doesn't exist.
		req, err := http.NewRequestWithContext(ctx, http.MethodDelete, "/v1/access/"+deletedAccess, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer authToken")
		rc := httptest.NewRecorder()
		res.ServeHTTP(rc, req)
		require.Equal(t, http.StatusOK, rc.Code)

		// Request an access grant that doesn't exist.
		// This request isn't rate limited because it's configured for allowing one
		// failure.
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, "/v1/access/"+deletedAccess, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer authToken")
		rc = httptest.NewRecorder()
		res.ServeHTTP(rc, req)
		require.Equal(t, http.StatusUnauthorized, rc.Code)

		// Request an existing access grant but verifies that it's rate-limited due
		// to the previous failed request.
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, "/v1/access/"+accessKeyID, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer authToken")
		rc = httptest.NewRecorder()
		res.ServeHTTP(rc, req)
		require.Equal(t, http.StatusTooManyRequests, rc.Code)

		rah := rc.Header().Get("Retry-After")
		ra, err := strconv.Atoi(rah)
		require.NoErrorf(
			t, err, "invalid Retry-After header value, expected an integer, got: %s ",
			rah,
		)
		require.Equal(t, 1, ra, "Retry-After seconds")
	})
}

func TestResources_getAccess_noLimiters(t *testing.T) {
	endpoint, err := url.Parse("http://endpoint.invalid/")
	require.NoError(t, err)
	allowed := map[storj.NodeID]struct{}{minimalAccessSatelliteID: {}}

	res := newResource(t, authdb.NewDatabase(memauth.New(), allowed), endpoint, nil)

	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	accessKeyID := createAccess(t, minimalAccess, res)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "/v1/access/"+accessKeyID, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer authToken")
	rc := httptest.NewRecorder()
	res.ServeHTTP(rc, req)
	require.Equal(t, http.StatusOK, rc.Code)

	deletedAccess := createAccess(t, generateAccessGrant(t, time.Time{}), res)

	// Delete the access grant for being able to request one that doesn't exist.
	req, err = http.NewRequestWithContext(ctx, http.MethodDelete, "/v1/access/"+deletedAccess, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer authToken")
	rc = httptest.NewRecorder()
	res.ServeHTTP(rc, req)
	require.Equal(t, http.StatusOK, rc.Code)

	// Request an access grant that doesn't exist several times.
	for i := 0; i < rand.Intn(100)+10; i++ {
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, "/v1/access/"+deletedAccess, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer authToken")
		rc = httptest.NewRecorder()
		res.ServeHTTP(rc, req)
		require.Equal(t, http.StatusUnauthorized, rc.Code)
	}

	// Request an existing access grant should be fine because they
	// rate-limiting isn't set.
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, "/v1/access/"+accessKeyID, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer authToken")
	rc = httptest.NewRecorder()
	res.ServeHTTP(rc, req)
	require.Equal(t, http.StatusOK, rc.Code)
}

func newResource(
	t *testing.T, db *authdb.Database, endpoint *url.URL, limiters *failrate.Limiters,
) *Resources {
	t.Helper()

	return New(zaptest.NewLogger(t), db, endpoint, "authToken", limiters)
}

// Generates a new valid access grant.
// It's restricted to be valid until notAfter unless that notAfter is the zero
// value.
func generateAccessGrant(t *testing.T, notAfter time.Time) string {
	t.Helper()

	key := testrand.Key()
	apiKey, err := macaroon.NewAPIKey(key[:])
	require.NoError(t, err)

	if !notAfter.IsZero() {
		apiKey, err = apiKey.Restrict(macaroon.Caveat{NotAfter: &notAfter})
		require.NoError(t, err)
	}

	inner := grant.Access{
		SatelliteAddress: "1SYXsAycDPUu4z2ZksJD5fh5nTDcH3vCFHnpcVye5XuL1NrYV@s",
		APIKey:           apiKey,
		EncAccess:        grant.NewEncryptionAccess(),
	}

	serialized, err := inner.Serialize()
	require.NoError(t, err)

	return serialized
}

// createAccess creates an access through the AuthService endpoint.
func createAccess(t *testing.T, accessGrant string, res *Resources) (accessKeyID string) {
	t.Helper()

	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	body := strings.NewReader(fmt.Sprintf(`{"access_grant": %q}`, accessGrant))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/v1/access", body)
	require.NoError(t, err)

	rc := httptest.NewRecorder()
	res.ServeHTTP(rc, req)
	require.Equal(t, http.StatusOK, rc.Code)

	var resBody struct {
		AccessKeyID string `json:"access_key_id"`
	}

	require.NoError(t, json.Unmarshal(rc.Body.Bytes(), &resBody))
	return resBody.AccessKeyID
}
