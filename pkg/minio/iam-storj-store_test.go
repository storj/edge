// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package minio

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"storj.io/minio/cmd"
	"storj.io/minio/pkg/auth"
)

func TestLoadUserBadURL(t *testing.T) {
	for _, badURL := range []string{"", "test.url.invalid", "http://test.url.invalid"} {
		store := GetTestAuthStore(badURL, "token", 2*time.Second)
		var buffer bytes.Buffer
		require.Error(t, store.GetObject(context.Background(), "", "config/iam/users/fakeUser/identity.json", 0, 0, &buffer, "", cmd.ObjectOptions{}))
	}
}

func TestLoadUserTimeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	store := GetTestAuthStore(ts.URL, "token", 100*time.Millisecond)

	authErr := make(chan error, 1)
	go func() {
		var buffer bytes.Buffer
		authErr <- store.GetObject(context.Background(), "", "config/iam/users/fakeUser/identity.json", 0, 0, &buffer, "", cmd.ObjectOptions{})
	}()

	select {
	case res := <-authErr:
		require.Error(t, res)
		require.True(t, strings.Contains(res.Error(), "timeout"))
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
		_, err := w.Write([]byte(`{"public":true, "secret_key":"", "access_grant":""}`))
		require.NoError(t, err)
	}))

	store := GetTestAuthStore(ts.URL, "token", 2*time.Second)
	var buffer bytes.Buffer
	err := store.GetObject(context.Background(), "", "config/iam/users/fakeUser/identity.json", 0, 0, &buffer, "", cmd.ObjectOptions{})
	require.NoError(t, err)
	require.False(t, firstAttempt)
}

func TestLoadUserResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(`{"public":true, "secret_key":"mysecretkey", "access_grant":"myaccessgrant"}`))
		require.NoError(t, err)
	}))

	store := GetTestAuthStore(ts.URL, "token", 2*time.Second)
	var buffer bytes.Buffer
	err := store.GetObject(context.Background(), "", "config/iam/users/fakeUser/identity.json", 0, 0, &buffer, "", cmd.ObjectOptions{})
	require.NoError(t, err)

	var identity cmd.UserIdentity
	err = json.NewDecoder(&buffer).Decode(&identity)
	require.NoError(t, err)
	require.Equal(t, cmd.UserIdentity{
		Version: 1,
		Credentials: auth.Credentials{
			AccessKey:   "fakeUser",
			AccessGrant: "myaccessgrant",
			SecretKey:   "mysecretkey",
			Status:      "on",
		},
	}, identity)
}

func TestObjectPathToUser(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "config/iam/users/someUser/identity.json",
			expected: "someUser",
		},
		{
			input:    "invalid",
			expected: "",
		},
		{
			input:    ".",
			expected: "",
		},
		{
			input:    "/",
			expected: "",
		},
		{
			input:    "//",
			expected: "",
		},
	}
	for i, tc := range tests {
		require.Equal(t, tc.expected, objectPathToUser(tc.input), i)
	}
}

func GetTestAuthStore(authURL, authToken string, timeout time.Duration) *IAMAuthStore {
	return &IAMAuthStore{authURL: authURL, authToken: authToken, timeout: timeout}
}
