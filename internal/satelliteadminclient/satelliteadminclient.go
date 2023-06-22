// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package satelliteadminclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zeebo/errs"

	"storj.io/common/uuid"
)

var (
	// Error is a class of satellite admin client errors.
	Error = errs.Class("satellite admin client")

	// ErrAPIKeyNotFound is an error for when the satellite couldn't find the key.
	ErrAPIKeyNotFound = Error.New("api key not found")
)

// Client is a satellite admin client.
type Client struct {
	baseURL   string
	authToken string
}

// New returns a new satellite admin client.
func New(baseURL, authToken string) *Client {
	return &Client{
		baseURL:   baseURL,
		authToken: authToken,
	}
}

// APIKey is a satellite api key.
type APIKey struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
}

// Project is a satellite project.
type Project struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

// User is a satellite user.
type User struct {
	ID       uuid.UUID `json:"id"`
	Email    string    `json:"email"`
	PaidTier bool      `json:"paidTier"`
}

// APIKeyResponse is a response when looking up API key information from the satellite.
type APIKeyResponse struct {
	APIKey  APIKey  `json:"api_key"`
	Project Project `json:"project"`
	Owner   User    `json:"owner"`
}

// GetAPIKey gets information on the given API key from the satellite.
func (c *Client) GetAPIKey(ctx context.Context, apiKey string) (*APIKeyResponse, error) {
	req, err := c.newRequest(ctx, http.MethodGet, "/api/apikeys/"+apiKey, nil)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	resp, err := c.doRequest(req)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	var apiResp APIKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, Error.Wrap(err)
	}
	return &apiResp, nil
}

// DeleteAPIKey deletes the given API key from the satellite.
func (c *Client) DeleteAPIKey(ctx context.Context, apiKey string) error {
	req, err := c.newRequest(ctx, http.MethodDelete, "/api/apikeys/"+apiKey, nil)
	if err != nil {
		return Error.Wrap(err)
	}
	resp, err := c.doRequest(req)
	if err != nil {
		return Error.Wrap(err)
	}
	_ = resp.Body.Close()
	return nil
}

func (c *Client) newRequest(ctx context.Context, method, uri string, body io.Reader) (*http.Request, error) {
	reqURL, err := url.JoinPath(c.baseURL, uri)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", c.authToken)

	return req, nil
}

func (c *Client) doRequest(req *http.Request) (*http.Response, error) {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return nil, ErrAPIKeyNotFound
		}
		return nil, apiError(resp)
	}

	return resp, nil
}

// APIError is a satellite admin API error.
type APIError struct {
	Status  string
	Message string `json:"error"`
	Detail  string `json:"detail"`
}

func (e APIError) Error() string {
	msg := fmt.Sprintf("unexpected status: %s", e.Status)
	if e.Message != "" {
		msg += fmt.Sprintf(": %q", e.Message)
	}
	if e.Detail != "" {
		msg += fmt.Sprintf(": %q", e.Detail)
	}
	return msg
}

func apiError(resp *http.Response) error {
	apiErr := APIError{
		Status: resp.Status,
	}

	contentType := func(value string) bool {
		for _, v := range resp.Header.Values("Content-Type") {
			mediatype, _, _ := mime.ParseMediaType(v)
			if strings.EqualFold(mediatype, value) {
				return true
			}
		}
		return false
	}

	switch {
	case resp.StatusCode >= 400 && contentType("application/json"):
		// ignore errors to speculatively decode error details if they exist.
		_ = json.NewDecoder(resp.Body).Decode(&apiErr)
		return apiErr
	default:
		return apiErr
	}
}
