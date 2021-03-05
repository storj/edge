// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package authc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/zeebo/errs"
)

// Error is the default error class for auth clients.
var Error = errs.Class("authc")

const (
	clientTimeout = 5 * time.Second
)

// Client data
type Client struct {
	client *http.Client
	token  string

	accessURL     *url.URL
	healthLiveURL *url.URL
}

// New returns a new auth client.
func New(baseURL *url.URL, token string) (*Client, error) {
	accessURL, err := baseURL.Parse("/v1/access")
	if err != nil {
		return nil, err
	}

	healthLiveURL, err := baseURL.Parse("/v1/health/live")
	if err != nil {
		return nil, err
	}

	return &Client{
		client: &http.Client{
			Timeout: clientTimeout,
		},
		token: token,

		accessURL:     accessURL,
		healthLiveURL: healthLiveURL,
	}, nil
}

// GetAccessResponse data
type GetAccessResponse struct {
	AccessGrant string `json:"access_grant"`
	SecretKey   string `json:"secret_key"`
	Public      bool   `json:"public"`
}

// GetAccess returns the auth service access data for the give access key ID.
func (c *Client) GetAccess(ctx context.Context, accessKeyID string) (response *GetAccessResponse, err error) {
	reqURL, err := c.accessURL.Parse(path.Join(c.accessURL.Path, accessKeyID))
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL.String(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.token)

	res, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, Error.New("unexpected response code %d %s", res.StatusCode, res.Status)
	}

	var gar GetAccessResponse

	err = json.NewDecoder(res.Body).Decode(&gar)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return &gar, nil
}

// GetHealthLive returns the auth service health live status.
func (c *Client) GetHealthLive(ctx context.Context) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.healthLiveURL.String(), nil)
	if err != nil {
		return false, Error.Wrap(err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)

	res, err := c.client.Do(req)
	if err != nil {
		return false, Error.Wrap(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return false, Error.New("unexpected response code %d %s", res.StatusCode, res.Status)
	}

	return true, nil
}
