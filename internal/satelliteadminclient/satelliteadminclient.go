// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package satelliteadminclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
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

	// ErrNotFound is an error returned when the resource did not exist.
	ErrNotFound = Error.New("not found")
)

// Client is a satellite admin client.
type Client struct {
	baseURL   string
	authToken string
	log       *log.Logger
}

// New returns a new satellite admin client.
func New(baseURL, authToken string, log *log.Logger) *Client {
	return &Client{
		baseURL:   baseURL,
		authToken: authToken,
		log:       log,
	}
}

// APIKey is a satellite api key.
type APIKey struct {
	ID        uuid.UUID `json:"id,omitempty"`
	Name      string    `json:"name,omitempty"`
	CreatedAt time.Time `json:"createdAt,omitempty"`
}

// Project is a satellite project.
type Project struct {
	ID   uuid.UUID `json:"id,omitempty"`
	Name string    `json:"name,omitempty"`
}

// User is a satellite user.
type User struct {
	ID       uuid.UUID `json:"id,omitempty"`
	FullName string    `json:"fullName,omitempty"`
	Email    string    `json:"email,omitempty"`
	PaidTier bool      `json:"paidTier,omitempty"`
}

// APIKeyResponse is a response when looking up API key information from the satellite.
type APIKeyResponse struct {
	APIKey  APIKey  `json:"api_key,omitempty"`
	Project Project `json:"project,omitempty"`
	Owner   User    `json:"owner,omitempty"`
}

// UserResponse is a response when looking up a user information from the satellite.
type UserResponse struct {
	User     User      `json:"user,omitempty"`
	Projects []Project `json:"projects,omitempty"`
}

// GetAPIKey gets information on the given API key from the satellite.
// See https://github.com/storj/storj/tree/main/satellite/admin#get-apiapikeysapikey
func (c *Client) GetAPIKey(ctx context.Context, apiKey string) (APIKeyResponse, error) {
	req, err := c.newRequest(ctx, http.MethodGet, "/api/apikeys/"+apiKey, nil)
	if err != nil {
		return APIKeyResponse{}, Error.Wrap(err)
	}
	resp, err := c.doRequest(req)
	if err != nil {
		return APIKeyResponse{}, Error.Wrap(err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	var r APIKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return r, Error.Wrap(err)
	}
	return r, nil
}

// DeleteAPIKey deletes the given API key from the satellite.
// See https://github.com/storj/storj/tree/main/satellite/admin#delete-apiapikeysapikey
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

// GetUser gets given user information from the satellite.
// See https://github.com/storj/storj/tree/main/satellite/admin#get-apiusersuser-email
func (c *Client) GetUser(ctx context.Context, email string) (UserResponse, error) {
	req, err := c.newRequest(ctx, http.MethodGet, "/api/users/"+email, nil)
	if err != nil {
		return UserResponse{}, Error.Wrap(err)
	}
	resp, err := c.doRequest(req)
	if err != nil {
		return UserResponse{}, Error.Wrap(err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	var r UserResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return r, Error.Wrap(err)
	}
	return r, nil
}

// ViolationFreezeAccount freezes the given user's account on the satellite so no upload or downloads may occur.
// See https://github.com/storj/storj/tree/main/satellite/admin#put-apiusersuser-emailviolation-freeze
func (c *Client) ViolationFreezeAccount(ctx context.Context, email string) error {
	req, err := c.newRequest(ctx, http.MethodPut, "/api/users/"+email+"/violation-freeze", nil)
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

// SetProjectLimits sets the project limits.
// See https://github.com/storj/storj/tree/main/satellite/admin#update-limits
func (c *Client) SetProjectLimits(ctx context.Context, projectID string, limits url.Values) error {
	req, err := c.newRequest(ctx, http.MethodPut, "/api/projects/"+projectID+"/limit?"+limits.Encode(), nil)
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
	start := time.Now()
	url := req.URL.String()
	c.log.Println("sending", req.Method, "request to satellite admin", url)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return nil, ErrNotFound
		}
		return nil, apiError(resp)
	}

	c.log.Println("received successful", req.Method, "from satellite admin", url, "(time taken:", time.Since(start), ")")

	return resp, nil
}

// APIError is a satellite admin API error.
type APIError struct {
	Status  string
	Message string `json:"message"`
	Detail  string `json:"detail"`
}

func (e APIError) Error() string {
	msg := "unexpected status: " + e.Status
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
