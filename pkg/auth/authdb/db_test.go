// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package authdb

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/common/encryption"
	"storj.io/common/grant"
	"storj.io/common/macaroon"
	"storj.io/common/storj"
	"storj.io/common/testcontext"
)

func TestBase32(t *testing.T) {
	oldKey, err := NewEncryptionKey()
	require.NoError(t, err)
	require.NotEqual(t, oldKey, EncryptionKey{})
	encoded := oldKey.ToBase32()
	require.Len(t, encoded, EncKeySizeEncoded)
	var newKey EncryptionKey
	err = newKey.FromBase32(encoded)
	require.NoError(t, err)
	require.Equal(t, newKey, oldKey)
	require.NotEqual(t, newKey, EncryptionKey{})
}

func TestBase32Fail(t *testing.T) {
	key, err := NewEncryptionKey()
	require.NoError(t, err)
	encoded := key.ToBase32()
	require.Len(t, encoded, EncKeySizeEncoded)
	require.Error(t, key.FromBase32(encoded[1:]))
	require.Error(t, key.FromBase32(encoded[2:]))
	encoded = "a" + encoded[1:]
	require.Error(t, key.FromBase32(encoded))
}

func TestNonceIncrement(t *testing.T) {
	nonce := storj.Nonce{}
	_, err := encryption.Increment(&nonce, 1)
	require.NoError(t, err)
	require.Equal(t, storj.Nonce{1}, nonce)
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

func TestPutSatelliteValidation(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()
	validURL := "12EayRS2V1kEsWESU9QMRseFhdxYxKicsiFmxrsLZHeLUtdps3S@us1.storj.io:7777"
	checkURL := "12EayRS2V1kEsWESU9QMRseFhdxYxKicsiFmxrsLZHeLUtdps3S@127.0.0.1:7778"

	mac, err := macaroon.NewAPIKey(nil)
	require.NoError(t, err)

	g := grant.Access{
		SatelliteAddress: checkURL,
		EncAccess:        grant.NewEncryptionAccess(),
		APIKey:           mac,
	}
	invalidGrant, err := g.Serialize()
	require.NoError(t, err)

	g.SatelliteAddress = validURL
	validGrant, err := g.Serialize()
	require.NoError(t, err)

	url, err := storj.ParseNodeURL(validURL)
	require.NoError(t, err)

	db, err := NewDatabase(zaptest.NewLogger(t), mockStorage{}, Config{
		AllowedSatelliteURLs: map[storj.NodeURL]struct{}{url: {}},
	})
	require.NoError(t, err)

	key, err := NewEncryptionKey()
	require.NoError(t, err)

	_, err = db.Put(ctx, key, validGrant, false)
	require.NoError(t, err)
	_, err = db.Put(ctx, key, invalidGrant, false)
	require.Error(t, err)
}

func TestPutShortExpiration(t *testing.T) {
	eu1 := "12L9ZFwhzVpuEKMUNUqkaTLGzwY9G24tbiigLiXpmZWKwmcNDDs@eu1.storj.io:7777"

	url, err := storj.ParseNodeURL(eu1)
	require.NoError(t, err)

	enc, err := NewEncryptionKey()
	require.NoError(t, err)

	api, err := macaroon.NewAPIKey(nil)
	require.NoError(t, err)

	g := grant.Access{
		SatelliteAddress: eu1,
		EncAccess:        grant.NewEncryptionAccess(),
		APIKey:           combineNotAfterCaveats(t, api, time.Unix(0, 0)),
	}
	s, err := g.Serialize()
	require.NoError(t, err)

	db, err := NewDatabase(zaptest.NewLogger(t), mockStorage{}, Config{
		AllowedSatelliteURLs: map[storj.NodeURL]struct{}{url: {}},
	})
	require.NoError(t, err)

	_, err = db.Put(context.TODO(), enc, s, true)
	t.Log(err)
	require.Error(t, err)
	require.True(t, ErrAccessGrant.Has(err))
}

type mockStorage struct{}

func (mockStorage) Put(ctx context.Context, keyHash KeyHash, record *Record) (err error) { return nil }
func (mockStorage) Get(ctx context.Context, keyHash KeyHash) (record *Record, err error) {
	return nil, nil
}
func (mockStorage) HealthCheck(ctx context.Context) error { return nil }
func (mockStorage) Run(ctx context.Context) error         { return nil }
func (mockStorage) Close() error                          { return nil }
