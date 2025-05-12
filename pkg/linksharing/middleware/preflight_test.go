// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"storj.io/edge/pkg/linksharing/middleware"
)

func TestPreflight(t *testing.T) {
	testCases := []struct {
		method                                                          string
		expectedStatus                                                  int
		expectedBody                                                    string
		expectedAllowOrigin, expectedAllowMethods, expectedAllowHeaders string
	}{
		{
			method:         "PUT",
			expectedStatus: http.StatusMethodNotAllowed,
			expectedBody:   "Method Not Allowed",
		},
		{
			method:         "DELETE",
			expectedStatus: http.StatusMethodNotAllowed,
			expectedBody:   "Method Not Allowed",
		},
		{
			method:               "OPTIONS",
			expectedStatus:       http.StatusOK,
			expectedAllowOrigin:  "*",
			expectedAllowMethods: "GET, HEAD",
			expectedAllowHeaders: "*",
		},
		{
			method:               "GET",
			expectedStatus:       http.StatusOK,
			expectedAllowOrigin:  "*",
			expectedAllowMethods: "GET, HEAD",
			expectedAllowHeaders: "*",
		},
		{
			method:               "HEAD",
			expectedStatus:       http.StatusOK,
			expectedAllowOrigin:  "*",
			expectedAllowMethods: "GET, HEAD",
			expectedAllowHeaders: "*",
		},
	}
	for _, tc := range testCases {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(tc.method, "/", nil)

		handler := middleware.Preflight(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		handler.ServeHTTP(rec, req)

		resp := rec.Result()
		require.NoError(t, resp.Body.Close())

		require.Equal(t, tc.expectedStatus, resp.StatusCode)
		require.Contains(t, rec.Body.String(), tc.expectedBody)
		require.Equal(t, tc.expectedAllowOrigin, resp.Header.Get("Access-Control-Allow-Origin"))
		require.Equal(t, tc.expectedAllowMethods, resp.Header.Get("Access-Control-Allow-Methods"))
		require.Equal(t, tc.expectedAllowHeaders, resp.Header.Get("Access-Control-Allow-Headers"))
	}
}
