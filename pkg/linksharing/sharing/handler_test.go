// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"storj.io/common/testcontext"
	"storj.io/gateway-mt/pkg/linksharing/objectmap"
)

func TestCompareHosts(t *testing.T) {
	same := [][2]string{
		{"website.test", "website.test"},
		{"website.test:443", "website.test"},
		{"website.test:443", "website.test:443"},
		{"website.test:443", "website.test:880"},
		{"192.168.0.1:443", "192.168.0.1:880"},
		{"[::1]:443", "[::1]:880"},
	}
	for _, test := range same {
		result, err := compareHosts(test[0], test[1])
		assert.NoError(t, err)
		assert.True(t, result)
	}

	notsame := [][2]string{
		{"website.test:443", "site.test:443"},
		{"website.test", "site.test"},
		{"[::1]:443", "[::2]:880"},
	}
	for _, test := range notsame {
		result, err := compareHosts(test[0], test[1])
		assert.NoError(t, err)
		assert.False(t, result)
	}
}

func TestHandler_CORS(t *testing.T) {
	check := func(method, path string) bool {
		rec := httptest.NewRecorder()

		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Authorization", "Bearer authToken")
		req.Header.Add("Origin", "http://example.com")

		cfg := Config{
			URLBases:  []string{"http://test.test"},
			Templates: "../../../pkg/linksharing/web/",
		}

		handler, err := NewHandler(&zap.Logger{}, &objectmap.IPDB{}, nil, nil, cfg)
		require.NoError(t, err)
		_ = handler.serveHTTP(testcontext.New(t), rec, req)

		result := rec.Result()
		require.NoError(t, result.Body.Close())

		respHeaders := result.Header.Get("Access-Control-Allow-Origin")
		if respHeaders != "*" {
			return false
		}
		respHeaders = result.Header.Get("Access-Control-Allow-Methods")
		if respHeaders != "GET, HEAD" {
			return false
		}
		respHeaders = result.Header.Get("Access-Control-Allow-Headers")
		return respHeaders == "*"
	}

	require.False(t, check("POST", "/health/process"))
	require.True(t, check("OPTIONS", "/health/process"))
	require.True(t, check("GET", "/health/process"))
	require.True(t, check("HEAD", "/health/process"))
	require.False(t, check("PUT", "/health/process"))
	require.False(t, check("DELETE", "/health/process"))
}
