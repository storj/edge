// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"storj.io/edge/pkg/linksharing/handlers"
)

func TestHealthCheckHandler(t *testing.T) {
	check := func(inShutdown *int32) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://test.test/health/process", nil)

		handler := handlers.NewHealthCheckHandler(inShutdown)
		handler.ServeHTTP(rec, req)

		resp := rec.Result()
		require.NoError(t, resp.Body.Close())

		return rec.Code
	}

	var inShutdown int32
	assert.Equal(t, http.StatusOK, check(&inShutdown))
	inShutdown = 1
	assert.Equal(t, http.StatusServiceUnavailable, check(&inShutdown))
}
