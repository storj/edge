// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package access

import (
	"time"

	"storj.io/common/macaroon"
)

// APIKeyExpiration returns the expiration time of apiKey, and any error
// encountered. It rejects expiration times that are before a minute from now.
//
// TODO: we should expose this functionality in the API Key type natively.
func APIKeyExpiration(apiKey *macaroon.APIKey) (*time.Time, error) {
	mac, err := macaroon.ParseMacaroon(apiKey.SerializeRaw())
	if err != nil {
		return nil, err
	}

	var expiration *time.Time
	for _, cavbuf := range mac.Caveats() {
		var cav macaroon.Caveat
		if err := cav.UnmarshalBinary(cavbuf); err != nil {
			return nil, err
		}
		if cav.NotAfter != nil {
			cavExpiration := *cav.NotAfter
			if expiration == nil || expiration.After(cavExpiration) {
				expiration = &cavExpiration
			}
		}
	}

	return expiration, nil
}
