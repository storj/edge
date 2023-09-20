// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package satelliteadminclient

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest"

	"storj.io/common/testcontext"
	"storj.io/common/uuid"
)

func TestErrorResponse(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		response    func(w http.ResponseWriter, r *http.Request)
		expectedErr error
	}{
		{
			name: "good response",
			response: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
			},
		},
		{
			name: "bad response",
			response: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
			},
			expectedErr: APIError{
				Status: "403 Forbidden",
			},
		},
		{
			name: "bad response error body",
			response: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				require.NoError(t, json.NewEncoder(w).Encode(&APIError{
					Status:  "403 Forbidden",
					Message: "there was a problem",
					Detail:  "some details here",
				}))
			},
			expectedErr: APIError{
				Status:  "403 Forbidden",
				Message: "there was a problem",
				Detail:  "some details here",
			},
		},
		{
			name: "not found response",
			response: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			expectedErr: ErrNotFound,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ctx := testcontext.New(t)
			defer ctx.Cleanup()

			srv := httptest.NewServer(http.HandlerFunc(tc.response))
			defer srv.Close()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
			require.NoError(t, err)

			client := New(srv.URL, "", newLogger(t))
			resp, err := client.doRequest(req) //nolint:bodyclose
			if err == nil {
				ctx.Check(resp.Body.Close)
			}
			if tc.expectedErr != nil {
				require.ErrorIs(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAPIKeyResponse(t *testing.T) {
	id, err := uuid.New()
	require.NoError(t, err)

	testResp := APIKeyResponse{
		APIKey:  APIKey{ID: id, Name: "test key"},
		Project: Project{ID: id, Name: "test project"},
		Owner:   User{ID: id, Email: "test@user.com"},
	}

	tests := []struct {
		name             string
		method           string
		response         func(w http.ResponseWriter, r *http.Request)
		expectedResponse APIKeyResponse
		expectedErr      error
	}{
		{
			name: "good response",
			response: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				require.NoError(t, json.NewEncoder(w).Encode(&testResp))
			},
			expectedResponse: testResp,
		},
		{
			name: "bad response",
			response: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
			},
			expectedErr: APIError{
				Status: "403 Forbidden",
			},
		},
		{
			name: "not found response",
			response: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			expectedErr: ErrNotFound,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ctx := testcontext.New(t)
			defer ctx.Cleanup()

			srv := httptest.NewServer(http.HandlerFunc(tc.response))
			defer srv.Close()

			client := New(srv.URL, "", newLogger(t))
			apiResp, err := client.GetAPIKey(ctx, "")
			if tc.expectedErr != nil {
				require.ErrorIs(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.expectedResponse, apiResp)
		})
	}
}

func TestUserResponse(t *testing.T) {
	id, err := uuid.New()
	require.NoError(t, err)

	testResp := UserResponse{
		User:     User{ID: id, Email: "test@user.com"},
		Projects: []Project{{ID: id, Name: "test project"}},
	}

	tests := []struct {
		name             string
		method           string
		response         func(w http.ResponseWriter, r *http.Request)
		expectedResponse UserResponse
		expectedErr      error
	}{
		{
			name: "good response",
			response: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				require.NoError(t, json.NewEncoder(w).Encode(&testResp))
			},
			expectedResponse: testResp,
		},
		{
			name: "bad response",
			response: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
			},
			expectedErr: APIError{
				Status: "403 Forbidden",
			},
		},
		{
			name: "not found response",
			response: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			expectedErr: ErrNotFound,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ctx := testcontext.New(t)
			defer ctx.Cleanup()

			srv := httptest.NewServer(http.HandlerFunc(tc.response))
			defer srv.Close()

			client := New(srv.URL, "", newLogger(t))
			apiResp, err := client.GetUser(ctx, "")
			if tc.expectedErr != nil {
				require.ErrorIs(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.expectedResponse, apiResp)
		})
	}
}

func TestNewRequest(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	logger := newLogger(t)

	client := New("http://localhost:10005", "123", logger)
	req, err := client.newRequest(ctx, http.MethodDelete, "/api/apikeys/456", nil)
	require.NoError(t, err)
	require.Equal(t, "http://localhost:10005/api/apikeys/456", req.URL.String())
	require.Equal(t, "123", req.Header.Get("Authorization"))

	client = New("http://localhost:8888//", "abc123", logger)
	req, err = client.newRequest(ctx, http.MethodGet, "//api/apikeys/456/", nil)
	require.NoError(t, err)
	require.Equal(t, "http://localhost:8888/api/apikeys/456/", req.URL.String())
	require.Equal(t, "abc123", req.Header.Get("Authorization"))

	client = New("test://////", "", logger)
	req, err = client.newRequest(ctx, http.MethodGet, "//api/apikeys/456/", nil)
	require.NoError(t, err)
	require.Equal(t, "test:///api/apikeys/456/", req.URL.String())
	require.Equal(t, "", req.Header.Get("Authorization"))
}

func TestAPIError(t *testing.T) {
	require.Equal(t, `unexpected status: 400 Bad Request: "something happened": "here's some more detail"`, APIError{
		Status:  "400 Bad Request",
		Message: "something happened",
		Detail:  "here's some more detail",
	}.Error())

	require.Equal(t, `unexpected status: 400 Bad Request: "something happened"`, APIError{
		Status:  "400 Bad Request",
		Message: "something happened",
	}.Error())

	require.Equal(t, "unexpected status: 400 Bad Request", APIError{
		Status: "400 Bad Request",
	}.Error())
}

func newLogger(t *testing.T) *log.Logger {
	logger, err := zap.NewStdLogAt(zaptest.NewLogger(t).Named("satelliteadminclient"), zapcore.DebugLevel)
	require.NoError(t, err)

	return logger
}
