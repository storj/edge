// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"context"
	"net/http"

	"github.com/btcsuite/btcutil/base58"
	"github.com/zeebo/errs"

	"storj.io/uplink"
)

// parseAccess parses access to identify if it's a valid access grant otherwise
// identifies as being an access key and request the Auth services to resolve
// it. clientIP is the IP of the client that originated the request and it's
// required to be sent to the Auth Service.
//
// It returns an error if the access grant is correctly encoded but it doesn't
// parse or if the Auth Service responds with an error.
func parseAccess(ctx context.Context, access string, cfg AuthServiceConfig, clientIP string) (_ *uplink.Access, err error) {
	defer mon.Task()(&ctx)(&err)
	wrappedParse := func(access string) (*uplink.Access, error) {
		parsed, err := uplink.ParseAccess(access)
		if err != nil {
			return nil, WithStatus(err, http.StatusBadRequest)
		}
		return parsed, nil
	}

	// production access grants are base58check encoded with version zero.
	if _, version, err := base58.CheckDecode(access); err == nil && version == 0 {
		return wrappedParse(access)
	}

	// otherwise, assume an access key.
	authResp, err := cfg.ResolveWithCache(ctx, access, clientIP)
	if err != nil {
		return nil, err
	}
	if !authResp.Public {
		return nil, WithStatus(errs.New("non-public access key id"), http.StatusForbidden)
	}

	return wrappedParse(authResp.AccessGrant)
}
