// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package authc

import (
	"context"

	"github.com/storj/minio/pkg/storj/middleware/signature"
)

// SecretGetter is a secret key getter client.
type SecretGetter struct {
	client *Client
}

var _ signature.SecretKeyGetter = (*SecretGetter)(nil)

// NewSecretGetter returns a secret key getter.
func NewSecretGetter(client *Client) *SecretGetter {
	return &SecretGetter{
		client: client,
	}
}

// Get returns the secret key for the given access key ID.
func (s *SecretGetter) Get(ctx context.Context, akid string) (string, error) {
	gar, err := s.client.GetAccess(ctx, akid)
	if err != nil {
		return "", err
	}

	return gar.SecretKey, err
}
