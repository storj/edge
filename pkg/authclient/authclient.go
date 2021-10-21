// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package authclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/zeebo/errs"

	"storj.io/gateway-mt/pkg/backoff"
)

// AuthError is the default error class for auth clients.
var AuthError = errs.Class("authclient")

// HTTPError is an error based on HTTP response codes.
type HTTPError int

// Error implements the Error interface.
func (e HTTPError) Error() string {
	return fmt.Sprintf("invalid status code: %d", e)
}

const (
	authUserPath    string = "/v1/access"
	healthCheckPath string = "/v1/health/live"
)

// AuthClient communicates with the Auth Service.
type AuthClient struct {
	client  *http.Client
	token   string
	timeout time.Duration
	backoff backoff.ExponentialBackoff

	accessURL     *url.URL
	healthLiveURL *url.URL
}

// New returns a new auth client.
func New(baseURL *url.URL, token string, timeout time.Duration) (*AuthClient, error) {
	if baseURL.Scheme != "http" && baseURL.Scheme != "https" {
		return nil, AuthError.New("unexpected scheme found in endpoint parameter %s", baseURL.Scheme)
	}
	if baseURL.Host == "" {
		return nil, AuthError.New("host missing in parameter %s", baseURL.Host)
	}

	accessURL, err := baseURL.Parse(authUserPath)
	if err != nil {
		return nil, AuthError.Wrap(err)
	}

	healthLiveURL, err := baseURL.Parse(healthCheckPath)
	if err != nil {
		return nil, AuthError.Wrap(err)
	}

	return &AuthClient{
		client: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{ResponseHeaderTimeout: timeout},
		},
		token:         token,
		accessURL:     accessURL,
		healthLiveURL: healthLiveURL,
		timeout:       timeout,
		backoff:       backoff.ExponentialBackoff{Min: 100 * time.Millisecond, Max: 5 * time.Minute},
	}, nil
}

// Access contains Access information from the Auth Service.
type Access struct {
	AccessGrant string `json:"access_grant"`
	SecretKey   string `json:"secret_key"`
	IsPublic    bool   `json:"public"`
}

// GetAccess returns the auth service access data for the give access key ID.
func (c *AuthClient) GetAccess(ctx context.Context, accessKeyID, forwardedFor string) (response *Access, err error) {
	reqURL, err := c.accessURL.Parse(path.Join(c.accessURL.Path, accessKeyID))
	if err != nil {
		return nil, AuthError.Wrap(err)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL.String(), nil)
	if err != nil {
		return nil, AuthError.Wrap(err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Forwarded", "for="+forwardedFor)

	delay := c.backoff
	for {
		resp, err := c.client.Do(req)
		if err != nil {
			if !delay.Maxed() {
				if err := delay.Wait(ctx); err != nil {
					return nil, AuthError.Wrap(err)
				}
				continue
			}
			return nil, AuthError.Wrap(err)
		}

		// Use an anonymous function for deferring the response close before the
		// next retry and not pilling it up when the method returns.
		retry, err := func() (retry bool, _ error) {
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode == http.StatusInternalServerError {
				return true, nil // auth only returns this for unexpected issues
			}

			if resp.StatusCode != http.StatusOK {
				return false, AuthError.Wrap(HTTPError(resp.StatusCode))
			}

			if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
				if !delay.Maxed() {
					return true, nil
				}
				return false, err
			}
			return false, nil
		}()

		if retry {
			if err := delay.Wait(ctx); err != nil {
				return nil, AuthError.Wrap(err)
			}
			continue
		}
		return response, AuthError.Wrap(err)
	}
}

// GetHealthLive returns the auth service health live status.
func (c *AuthClient) GetHealthLive(ctx context.Context) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.healthLiveURL.String(), nil)
	if err != nil {
		return false, AuthError.Wrap(err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)

	res, err := c.client.Do(req)
	if err != nil {
		return false, AuthError.Wrap(err)
	}
	defer func() { err = errs.Combine(err, AuthError.Wrap(res.Body.Close())) }()

	if res.StatusCode != http.StatusOK {
		return false, AuthError.New("unexpected response code %d %s", res.StatusCode, res.Status)
	}

	return true, nil
}
