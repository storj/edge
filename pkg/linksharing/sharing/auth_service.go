// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/zeebo/errs"

	"storj.io/common/lrucache"
	"storj.io/gateway-mt/pkg/backoff"
)

// AuthServiceConfig describes configuration necessary to interact with the auth service.
type AuthServiceConfig struct {
	// Base url to use for the auth service to resolve access key ids
	BaseURL string

	// Authorization token used for the auth service to resolve access key ids.
	Token string

	// How long to wait for a single connection to complete before failing.
	Timeout time.Duration

	// Defines strategy for retrying requests to authservice.
	Backoff backoff.ExponentialBackoff

	// Cache is used for caching authservice's responses.
	Cache *lrucache.ExpiringLRU
}

// AuthServiceResponse is the struct representing the response from the auth service.
type AuthServiceResponse struct {
	AccessGrant string `json:"access_grant"`
	Public      bool   `json:"public"`
}

// AuthServiceError wraps all the errors returned when resolving an access key.
var AuthServiceError = errs.Class("auth service")

// Resolve maps an access key into an auth service response. clientIP is the IP
// of the client that originated the request and it's required to be sent to the
// Auth Service.
func (a AuthServiceConfig) Resolve(ctx context.Context, accessKeyID string, clientIP string) (_ *AuthServiceResponse, err error) {
	defer mon.Task()(&ctx)(&err)

	reqURL, err := url.Parse(a.BaseURL)
	if err != nil {
		return nil, WithStatus(AuthServiceError.Wrap(err),
			http.StatusInternalServerError)
	}

	reqURL.Path = path.Join(reqURL.Path, "/v1/access", accessKeyID)
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL.String(), nil)
	if err != nil {
		return nil, WithStatus(AuthServiceError.Wrap(err),
			http.StatusInternalServerError)
	}
	req.Header.Set("Authorization", "Bearer "+a.Token)
	req.Header.Set("Forwarded", "for="+clientIP)

	delay := a.Backoff
	client := http.Client{Timeout: a.Timeout}
	for {
		resp, err := client.Do(req)
		if err != nil {
			if !delay.Maxed() {
				if err := delay.Wait(ctx); err != nil {
					return nil, WithStatus(AuthServiceError.Wrap(err), httpStatusClientClosedRequest)
				}
				continue
			}
			return nil, WithStatus(AuthServiceError.Wrap(err),
				http.StatusInternalServerError)
		}

		// Use an anonymous function for deferring the response close before the
		// next retry and not pilling it up when the method returns.
		retry, authResp, err := func() (retry bool, _ *AuthServiceResponse, _ error) {
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode == http.StatusInternalServerError {
				return true, nil, nil // auth only returns this for unexpected issues
			}

			if resp.StatusCode != http.StatusOK {
				return false, nil, WithStatus(
					AuthServiceError.New("invalid status code: %d", resp.StatusCode),
					resp.StatusCode)
			}

			var authResp AuthServiceResponse
			if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
				if !delay.Maxed() {
					return true, nil, nil
				}
				return false, nil, WithStatus(AuthServiceError.Wrap(err),
					http.StatusInternalServerError)
			}

			return false, &authResp, nil
		}()

		if retry {
			if err := delay.Wait(ctx); err != nil {
				return nil, WithStatus(AuthServiceError.Wrap(err), httpStatusClientClosedRequest)
			}
			continue
		}

		return authResp, err
	}
}

// ResolveWithCache is like Resolve, but it uses the underlying LRU cache to
// cache and returns cached authservice's successful responses if caching is
// enabled.
func (a AuthServiceConfig) ResolveWithCache(ctx context.Context, accessKeyID string, clientIP string) (_ *AuthServiceResponse, err error) {
	defer mon.Task()(&ctx)(&err)

	if a.Cache == nil {
		return a.Resolve(ctx, accessKeyID, clientIP)
	}

	type cachedAuthServiceResponse struct {
		response *AuthServiceResponse
		err      error
	}

	v, err := a.Cache.Get(accessKeyID, func() (interface{}, error) {
		response, err := a.Resolve(ctx, accessKeyID, clientIP)

		switch GetStatus(err, http.StatusOK) {
		case http.StatusOK, http.StatusNotFound:
			return cachedAuthServiceResponse{response: response, err: err}, nil
		default:
			return cachedAuthServiceResponse{}, err // err is already wrapped
		}
	})
	if err != nil {
		return nil, err // err is already wrapped
	}

	response := v.(cachedAuthServiceResponse)

	return response.response, response.err
}
