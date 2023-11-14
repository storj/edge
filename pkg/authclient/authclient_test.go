// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package authclient

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"storj.io/edge/pkg/errdata"
)

const testKey = "jwaohtj3dhixxfpzhwj522x7z3pb"

func TestLoadUserBadURL(t *testing.T) {
	for _, badURL := range []string{"", "test.url.invalid", "http://test.url.invalid"} {
		client, err := GetTestAuthClient(t, badURL, "token", 100*time.Millisecond)
		if err == nil {
			client.BackOff.Max = 100 * time.Millisecond
			_, err = client.Resolve(context.Background(), testKey, "127.0.0.1")
		}
		require.Error(t, err, badURL)
	}
}

func TestInvalidKey(t *testing.T) {
	client, err := GetTestAuthClient(t, "test.url", "token", 100*time.Millisecond)
	require.NoError(t, err)

	_, err = client.Resolve(context.Background(), "notvalid", "127.0.0.1")
	require.Error(t, err)
}

func TestLoadUserTimeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client, err := GetTestAuthClient(t, ts.URL, "token", 100*time.Millisecond)
	client.BackOff.Max = 100 * time.Millisecond
	require.NoError(t, err)

	authErr := make(chan error, 1)
	go func() {
		_, err := client.Resolve(context.Background(), testKey, "127.0.0.1")
		authErr <- err
	}()

	select {
	case res := <-authErr:
		require.Error(t, res)
		require.True(t, strings.Contains(strings.ToLower(res.Error()), "timeout"))
	case <-time.After(1 * time.Second):
		require.Fail(t, "Bad LoadUser request should have timed out already")
	}
}

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
	defer ts.Close()

	client, err := GetTestAuthClient(t, ts.URL, "token", 2*time.Second)
	require.NoError(t, err)
	asr, err := client.Resolve(context.Background(), testKey, "127.0.0.1")
	require.NoError(t, err)
	require.False(t, firstAttempt)
	require.Equal(t, "ag", asr.AccessGrant)
}

func TestLoadUserResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(`{"public":true, "secret_key":"mysecretkey", "access_grant":"myaccessgrant"}`))
		require.NoError(t, err)
	}))
	defer ts.Close()

	client, err := GetTestAuthClient(t, ts.URL, "token", 2*time.Second)
	require.NoError(t, err)
	access, err := client.Resolve(context.Background(), testKey, "127.0.0.1")
	require.NoError(t, err)

	require.Equal(t, true, access.Public)
	require.Equal(t, "myaccessgrant", access.AccessGrant)
	require.Equal(t, "mysecretkey", access.SecretKey)
}

func TestBadStatusPassedThrough(t *testing.T) {
	tests := []struct {
		status int
	}{
		{status: http.StatusNotFound},
		{status: http.StatusBadRequest},
		{status: http.StatusUnauthorized},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(fmt.Sprintf("HTTP %d", tc.status), func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
			}))
			defer ts.Close()

			client, err := GetTestAuthClient(t, ts.URL, "token", 2*time.Second)
			require.NoError(t, err)
			_, err = client.ResolveWithCache(context.Background(), testKey, "127.0.0.1")
			require.Error(t, err)
			require.Equal(t, tc.status, errdata.GetStatus(err, http.StatusOK))
		})
	}
}

func GetTestAuthClient(t *testing.T, baseURL, token string, timeout time.Duration) (*AuthClient, error) {
	return New(Config{BaseURL: baseURL, Token: token, Timeout: timeout}), nil
}
