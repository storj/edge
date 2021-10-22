// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"context"
	"encoding/json"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"storj.io/common/lrucache"
	"storj.io/common/testcontext"
	"storj.io/gateway-mt/pkg/errdata"
)

func TestLoadUserRetry(t *testing.T) {
	firstAttempt := true
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if firstAttempt {
			firstAttempt = false
			return // writing nothing will cause an http.Client error
		}
		_, err := w.Write([]byte(`{"public":true, "secret_key":"", "access_grant":"ag"}`))
		require.NoError(t, err)
	}))
	asc := AuthServiceConfig{BaseURL: ts.URL, Token: "token"}
	asr, err := asc.Resolve(context.Background(), "fakeUser", "192.168.1.50")
	require.NoError(t, err)
	require.Equal(t, "ag", asr.AccessGrant)
	require.False(t, firstAttempt)
}

func TestAuthServiceConfig_Resolve(t *testing.T) {
	var (
		token       = "the-authentication-token-" + strconv.Itoa(rand.Int())
		accessKeyID = "key-id-" + strconv.Itoa(rand.Int())
		clientIP    = "192.168.50." + strconv.Itoa(rand.Intn(256))
		accessGrant = "thisIsTheAccessGrant" + strconv.Itoa(rand.Int())
	)

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkRequestMeta(t, r, accessKeyID, token, clientIP)

		_, err := w.Write([]byte(`{"public":true,"access_grant":"` + accessGrant + `"}`))
		require.NoError(t, err, "response writer error")
	}))
	defer testServer.Close()

	svc := AuthServiceConfig{
		BaseURL: testServer.URL,
		Token:   token,
	}

	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	t.Run("Resolve", func(t *testing.T) {
		resp, err := svc.Resolve(ctx, accessKeyID, clientIP)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, accessGrant, resp.AccessGrant, "response: access_grant")
		require.True(t, resp.Public, "response: public")
	})
	t.Run("ResolveWithCache with caching disabled", func(t *testing.T) {
		resp, err := svc.ResolveWithCache(ctx, accessKeyID, clientIP)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, accessGrant, resp.AccessGrant, "response: access_grant")
		require.True(t, resp.Public, "response: public")
	})
}

func TestAuthServiceConfig_ResolveWithCache(t *testing.T) {
	const (
		accessKeyID = "access-key-id"
		token       = "token"
		clientIP    = "192.168.50.1"
		accessGrant = "access-grant"
	)

	t.Run("OK", func(t *testing.T) {
		var shouldHitCache bool

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			checkRequestMeta(t, r, accessKeyID, token, clientIP)

			if shouldHitCache {
				t.Error("The lookup should have hit the cache")
			}

			shouldHitCache = true

			resp := AuthServiceResponse{AccessGrant: accessGrant, Public: true}

			require.NoError(t, json.NewEncoder(w).Encode(resp))
		}))
		defer ts.Close()

		service := AuthServiceConfig{
			BaseURL: ts.URL,
			Token:   token,
			Cache: lrucache.New(
				lrucache.Options{
					Expiration: time.Hour,
					Capacity:   1,
				},
			),
		}

		ctx := testcontext.New(t)
		defer ctx.Cleanup()

		for i := 0; i < 10; i++ {
			resp, err := service.ResolveWithCache(ctx, accessKeyID, clientIP)
			require.NoError(t, err)
			assert.Equal(t, accessGrant, resp.AccessGrant)
			assert.Equal(t, true, resp.Public)
		}
	})

	t.Run("Not Found", func(t *testing.T) {
		var shouldHitCache bool

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			checkRequestMeta(t, r, accessKeyID, token, clientIP)

			if shouldHitCache {
				t.Error("The lookup should have hit the cache")
			}

			shouldHitCache = true

			w.WriteHeader(http.StatusNotFound)
		}))
		defer ts.Close()

		service := AuthServiceConfig{
			BaseURL: ts.URL,
			Token:   token,
			Cache: lrucache.New(
				lrucache.Options{
					Expiration: time.Hour,
					Capacity:   1,
				},
			),
		}

		ctx := testcontext.New(t)
		defer ctx.Cleanup()

		for i := 0; i < 10; i++ {
			resp, err := service.ResolveWithCache(ctx, accessKeyID, clientIP)
			assert.Error(t, err)

			t.Logf("ResolveWithCache: %v", err)

			assert.Nil(t, resp)
		}
	})

	t.Run("not OK and not Not Found", func(t *testing.T) {
		const expectedCacheMisses = 10

		var cacheMisses int

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			checkRequestMeta(t, r, accessKeyID, token, clientIP)

			cacheMisses++

			w.WriteHeader(errdata.HTTPStatusClientClosedRequest)
		}))
		defer ts.Close()

		service := AuthServiceConfig{
			BaseURL: ts.URL,
			Token:   token,
			Cache: lrucache.New(
				lrucache.Options{
					Expiration: time.Hour,
					Capacity:   expectedCacheMisses,
				},
			),
		}

		ctx := testcontext.New(t)
		defer ctx.Cleanup()

		for i := 0; i < expectedCacheMisses; i++ {
			resp, err := service.ResolveWithCache(ctx, accessKeyID, clientIP)
			assert.Error(t, err)

			t.Logf("ResolveWithCache: %v", err)

			assert.Nil(t, resp)
		}

		assert.Equal(t, expectedCacheMisses, cacheMisses)
	})
}

func checkRequestMeta(t *testing.T, r *http.Request, accessKeyID, token, clientIP string) {
	assert.Equal(t, http.MethodGet, r.Method)
	assert.Equal(t, "/v1/access/"+accessKeyID, r.URL.EscapedPath())
	assert.Equal(t, "Bearer "+token, r.Header.Get("Authorization"))
	assert.Equal(t, "for="+clientIP, r.Header.Get("Forwarded"))
}
