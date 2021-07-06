// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/zeebo/errs"
)

// AuthError is the default error class for auth clients.
var AuthError = errs.Class("authclient")

const (
	clientTimeout = 5 * time.Second
)

// AuthClient communicates with the Auth Service.
type AuthClient struct {
	client *http.Client
	token  string

	accessURL     *url.URL
	healthLiveURL *url.URL
}

// NewAuthClient returns a new auth client.
func NewAuthClient(baseURL *url.URL, token string) (*AuthClient, error) {
	accessURL, err := baseURL.Parse("/v1/access")
	if err != nil {
		return nil, err
	}

	healthLiveURL, err := baseURL.Parse("/v1/health/live")
	if err != nil {
		return nil, err
	}

	return &AuthClient{
		client: &http.Client{
			Timeout: clientTimeout,
		},
		token:         token,
		accessURL:     accessURL,
		healthLiveURL: healthLiveURL,
	}, nil
}

// GetAccessResponse contains Access information from the Auth Service.
type GetAccessResponse struct {
	AccessGrant string `json:"access_grant"`
	SecretKey   string `json:"secret_key"`
	IsPublic    bool   `json:"public"`
}

// GetAccess returns the auth service access data for the give access key ID.
// clientIP is the IP of the client that has originated the request and it's
// required to be sent to the Auth service.
func (c *AuthClient) GetAccess(ctx context.Context, accessKeyID string, clientIP string) (response *GetAccessResponse, err error) {
	reqURL, err := c.accessURL.Parse(path.Join(c.accessURL.Path, accessKeyID))
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL.String(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Forwarded", "for="+clientIP)

	res, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { err = errs.Combine(err, AuthError.Wrap(res.Body.Close())) }()

	if res.StatusCode != http.StatusOK {
		return nil, AuthError.New("unexpected response code %d %s", res.StatusCode, res.Status)
	}

	var gar GetAccessResponse

	err = json.NewDecoder(res.Body).Decode(&gar)
	if err != nil {
		return nil, AuthError.Wrap(err)
	}

	return &gar, nil
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
