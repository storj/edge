// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"context"
	"net/http"
	"time"

	"github.com/zeebo/errs"

	"storj.io/common/base58"
	"storj.io/gateway-mt/pkg/authclient"
	"storj.io/gateway-mt/pkg/errdata"
	"storj.io/gateway-mt/pkg/linksharing/sharing/internal/signed"
	"storj.io/uplink"
)

// parseAccess guesses whether access is an access grant or Access Key ID. If
// latter, it contacts authservice to resolve it. If the resolved access grant
// isn't public, it will assume r is AWS Signature Version 4-signed if it
// contains a valid signature. signedAccessValidityTolerance is how much r's
// signature time can be skewed. clientIP is the IP of the client that
// originated the request and cannot be empty.
func parseAccess(
	ctx context.Context,
	r *http.Request,
	access string,
	signedAccessValidityTolerance time.Duration,
	cfg *authclient.AuthClient,
	clientIP string,
) (_ *uplink.Access, err error) {
	defer mon.Task()(&ctx)(&err)

	wrappedParse := func(access string) (*uplink.Access, error) {
		parsed, err := uplink.ParseAccess(access)
		if err != nil {
			return nil, errdata.WithStatus(err, http.StatusBadRequest)
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
	if !authResp.Public { // If credentials aren't public, assume signed request.
		if err = signed.VerifySigningInfo(r, authResp.SecretKey, time.Now(), signedAccessValidityTolerance); err != nil {
			if errs.Is(err, signed.ErrMissingAuthorizationHeader) {
				return nil, errdata.WithStatus(errs.New("non-public Access Key ID"), http.StatusForbidden)
			}
			return nil, errdata.WithStatus(err, http.StatusForbidden)
		}
	}

	return wrappedParse(authResp.AccessGrant)
}
