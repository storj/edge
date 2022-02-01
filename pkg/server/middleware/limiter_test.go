// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"storj.io/common/grant"
	"storj.io/common/macaroon"
	"storj.io/common/testcontext"
	"storj.io/gateway-mt/pkg/authclient"
)

const maxConncurrent = 3

func TestNewMacaroonLimiter(t *testing.T) {
	var next = make(chan struct{})
	var done = make(chan struct{}, maxConncurrent*2*3)
	var allTests = make(chan struct{})
	rateLimiter := NewMacaroonLimiter(maxConncurrent,
		func(w http.ResponseWriter, r *http.Request) {
			next <- struct{}{} // create in-order results
			http.Error(w, "", http.StatusTooManyRequests)
		},
	)

	// run ratelimiter cleanup until end of test
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	// make the default HTTP handler return StatusOK after waiting
	handler := rateLimiter.Limit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		next <- struct{}{} // create in-order results
		<-allTests
	}))

	// expect burst number of successes
	creds1 := getCredentials(t)
	testWithMacaroon(ctx, t, creds1, handler, next, done)
	// expect similar results for a different apiKey / macaroon
	creds2 := getCredentials(t)
	testWithMacaroon(ctx, t, creds2, handler, next, done)
	// expect similar results for a different apiKey / macaroon
	creds3 := getCredentials(t)
	testWithMacaroon(ctx, t, creds3, handler, next, done)
	close(allTests)

	// wait for previous responses to arrive so we can retest cred1
	for x := 0; x < maxConncurrent*2*3; x++ {
		<-done
	}
	// expect burst number of successes with cred1 again
	allTests = make(chan struct{})
	testWithMacaroon(ctx, t, creds1, handler, next, done)
	close(allTests)
}

func testWithMacaroon(ctx *testcontext.Context, t *testing.T, creds *Credentials, handler http.Handler, next, done chan struct{}) {
	// expect maxConncurrent HTTP 200s, then maxConncurrent HTTP 429s
	for x := 0; x < maxConncurrent*2; x++ {
		localX := x
		ctx.Go(func() error {
			responseCode := doRequest(ctx, t, creds, handler)
			if localX < maxConncurrent {
				assert.Equal(t, http.StatusOK, responseCode, localX)
			} else {
				assert.Equal(t, http.StatusTooManyRequests, responseCode, localX)
			}
			done <- struct{}{}
			return nil
		})
		<-next // wait until concurrency middleware has recorded the previous request
	}
}

func doRequest(ctx context.Context, t *testing.T, creds *Credentials, handler http.Handler) int {
	credCtx := context.WithValue(ctx, credentialsCV{}, creds)
	req, err := http.NewRequestWithContext(credCtx, "GET", "", nil)
	require.NoError(t, err)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr.Code
}

func getCredentials(t *testing.T) *Credentials {
	apiKey, err := macaroon.NewAPIKey([]byte("secret"))
	require.NoError(t, err)
	ag := grant.Access{
		SatelliteAddress: "satelliteAddress",
		APIKey:           apiKey,
		EncAccess:        grant.NewEncryptionAccess(),
	}
	grant, err := ag.Serialize()
	require.NoError(t, err)
	return &Credentials{
		AccessKey: "accessKey",
		AuthServiceResponse: authclient.AuthServiceResponse{
			AccessGrant: grant,
			SecretKey:   "secretKey",
			Public:      true,
		},
		Error: nil,
	}
}

func simpleKeyFunc(r *http.Request) (string, error) {
	return strconv.Itoa(r.ProtoMajor), nil
}
func noopHandler(w http.ResponseWriter, r *http.Request) {}

// How quickly can we go through 10 clients with 100 requests, with 10 request
// limits for each?
func benchmarkLimiter(l *Limiter) error {
	var g errgroup.Group
	for i := 0; i < 10; i++ {
		j := i
		g.Go(func() error {
			r := &http.Request{ProtoMajor: j}
			var g2 errgroup.Group
			for k := 0; k < 100; k++ {
				g2.Go(func() error {
					l.Limit(http.HandlerFunc(noopHandler)).ServeHTTP(nil, r)
					return nil
				})
			}
			return g2.Wait()
		})
	}
	return g.Wait()
}
func BenchmarkLimiter(b *testing.B) {
	l := NewLimiter(10, simpleKeyFunc, noopHandler)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		require.NoError(b, benchmarkLimiter(l))
	}
}
