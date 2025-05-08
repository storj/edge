// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package access_test

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"storj.io/common/macaroon"
	internalAccess "storj.io/edge/internal/access"
)

func TestAPIKeyExpiration(t *testing.T) {
	unrestricted, err := macaroon.NewAPIKey([]byte("test"))
	require.NoError(t, err)

	withUnrelatedCaveats, err := unrestricted.Restrict(macaroon.Caveat{DisallowReads: true})
	require.NoError(t, err)
	withUnrelatedCaveats, err = withUnrelatedCaveats.Restrict(macaroon.Caveat{NotBefore: &time.Time{}})
	require.NoError(t, err)

	// a, b and c are times in the order of appearance:
	a := time.Now().Add(time.Hour)
	b := a.Add(1)
	c := b.Add(1)

	tests := [...]struct {
		apiKey *macaroon.APIKey
		want   *time.Time
	}{
		{unrestricted, nil},
		{withUnrelatedCaveats, nil},
		{combineNotAfterCaveats(t, unrestricted, a), &a},
		{combineNotAfterCaveats(t, unrestricted, a, b), &a},
		{combineNotAfterCaveats(t, unrestricted, b, a), &a},
		{combineNotAfterCaveats(t, unrestricted, a, b, c), &a},
		{combineNotAfterCaveats(t, unrestricted, a, c, b), &a},
		{combineNotAfterCaveats(t, unrestricted, b, a, c), &a},
		{combineNotAfterCaveats(t, unrestricted, b, c, a), &a},
		{combineNotAfterCaveats(t, unrestricted, c, a, b), &a},
		{combineNotAfterCaveats(t, unrestricted, c, b, a), &a},
	}

	for i, tt := range tests {
		got, err := internalAccess.APIKeyExpiration(tt.apiKey)
		require.NoError(t, err, i)
		if tt.want != nil {
			require.Equal(t, tt.want.UTC(), got.UTC(), i)
		} else {
			require.Equal(t, tt.want, got, i)
		}
	}
}

func TestAPIKeyExpiration_Invalid(t *testing.T) {
	mac, err := macaroon.NewUnrestricted([]byte("test"))
	require.NoError(t, err)
	mac, err = mac.AddFirstPartyCaveat([]byte("\xff\xfftrash\xff\xff"))
	require.NoError(t, err)

	k, err := macaroon.ParseRawAPIKey(mac.Serialize())
	require.NoError(t, err)

	_, err = internalAccess.APIKeyExpiration(k) // first caveat is invalid
	require.Error(t, err)

	k, err = k.Restrict(macaroon.Caveat{NotAfter: &time.Time{}})
	require.NoError(t, err)
	k, err = k.Restrict(macaroon.Caveat{DisallowDeletes: true})
	require.NoError(t, err)

	_, err = internalAccess.APIKeyExpiration(k) // one of the caveats is invalid
	require.Error(t, err)
}

func combineNotAfterCaveats(t *testing.T, unrestricted *macaroon.APIKey, times ...time.Time) *macaroon.APIKey {
	var (
		restricted = unrestricted
		err        error
	)

	for i, time := range times {
		restricted, err = restricted.Restrict(macaroon.Caveat{NotAfter: &time})
		require.NoError(t, err)
		if i%2 == 0 { // add noise
			restricted, err = restricted.Restrict(macaroon.Caveat{AllowedPaths: []*macaroon.Caveat_Path{{Bucket: []byte(strconv.Itoa(i))}}})
			require.NoError(t, err)
		}
	}

	return restricted
}
