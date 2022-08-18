// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package authclient

import (
	"net/http"
	"net/url"
	"time"

	"github.com/zeebo/errs"

	"storj.io/gateway-mt/pkg/backoff"
	"storj.io/gateway-mt/pkg/errdata"
)

// AuthServiceError wraps all the errors returned when resolving an access key.
var AuthServiceError = errs.Class("auth service")

// Config describes configuration necessary to interact with the auth service.
type Config struct {
	BaseURL string        `user:"true" help:"base url to use for resolving access key ids" releaseDefault:"" devDefault:"http://localhost:20000"`
	Token   string        `user:"true" help:"auth token for giving access to the auth service" releaseDefault:"" devDefault:"super-secret"`
	Timeout time.Duration `user:"true" help:"how long to wait for a single auth service connection" default:"10s"`
	BackOff backoff.ExponentialBackoff
	Cache   AuthServiceCacheConfig
}

// Validate checks if the configuration value are valid.
func (a Config) Validate() error {
	if a.Token == "" {
		return AuthServiceError.New("token parameter is missing")
	}
	reqURL, err := url.Parse(a.BaseURL)
	if err != nil {
		return errdata.WithStatus(AuthServiceError.Wrap(err), http.StatusInternalServerError)
	}
	if reqURL.Scheme != "http" && reqURL.Scheme != "https" {
		return AuthServiceError.New("unexpected scheme found in endpoint parameter %s", reqURL.Scheme)
	}
	if reqURL.Host == "" {
		return AuthServiceError.New("host missing in parameter %s", reqURL.Host)
	}
	return nil
}

// AuthServiceCacheConfig describes configuration necessary to cache the results of auth service lookups.
type AuthServiceCacheConfig struct {
	Expiration time.Duration `user:"true" help:"how long to keep cached access grants in cache" default:"24h"`
	Capacity   int           `user:"true" help:"how many cached access grants to keep in cache" default:"10000"`
}

// AuthServiceResponse is the struct representing the response from the auth service.
type AuthServiceResponse struct {
	AccessGrant string `json:"access_grant"`
	SecretKey   string `json:"secret_key"`
	Public      bool   `json:"public"`
}
