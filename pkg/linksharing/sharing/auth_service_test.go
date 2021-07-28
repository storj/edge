// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"context"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"storj.io/common/testcontext"
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
	t.Run("Authservice request", func(t *testing.T) {
		var (
			token       = "the-authentication-token-" + strconv.Itoa(rand.Int())
			accessKeyID = "key-id-" + strconv.Itoa(rand.Int())
			clientIP    = "192.168.50." + strconv.Itoa(rand.Intn(256))
			accessGrant = "thisIsTheAccessGrant" + strconv.Itoa(rand.Int())
		)

		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, http.MethodGet, r.Method, "http request method")
			require.Equal(t, "/v1/access/"+accessKeyID, r.URL.Path, "http request path")
			require.Equal(t, r.Header.Get("Authorization"), "Bearer "+token)
			require.Equal(t, r.Header.Get("Forwarded"), "for="+clientIP, "Forwarded header")

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

		resp, err := svc.Resolve(ctx, accessKeyID, clientIP)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, accessGrant, resp.AccessGrant, "response access grant")
		require.True(t, resp.Public, "response access grant")
	})
}
