// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package authdb

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"storj.io/common/testrand"
)

func TestKeyHash(t *testing.T) {
	data := testrand.RandAlphaNumeric(32)

	var kh KeyHash
	require.NoError(t, kh.SetBytes(data))
	require.Equal(t, data, kh.Bytes())

	var kh2 KeyHash
	encoded := kh.ToHex()
	require.Len(t, encoded, KeyHashSizeEncoded)
	require.Error(t, kh2.FromHex(encoded[1:]))
	require.Equal(t, KeyHash{}, kh2)
	require.Error(t, kh2.FromHex("g"+encoded[1:]))
	require.Equal(t, KeyHash{}, kh2)
	require.NoError(t, kh2.FromHex(encoded))
	require.Equal(t, kh, kh2)
}

func TestWithinDuration(t *testing.T) {
	date := time.Now()
	margin := time.Minute
	dateSlightlyOff := time.Now().Add(30 * time.Second)
	dateBeyondMargin := date.Add(2 * time.Minute)

	tests := []struct {
		desc             string
		record1, record2 FullRecord
		equal            bool
	}{
		{
			desc:  "empty records",
			equal: true,
		},
		{
			desc:    "identical records created date",
			record1: FullRecord{CreatedAt: date},
			record2: FullRecord{CreatedAt: date},
			equal:   true,
		},
		{
			desc:    "created date within margin of error",
			record1: FullRecord{CreatedAt: date},
			record2: FullRecord{CreatedAt: dateSlightlyOff},
			equal:   true,
		},
		{
			desc:    "records with differing created date",
			record1: FullRecord{CreatedAt: date},
			record2: FullRecord{CreatedAt: dateBeyondMargin},
			equal:   false,
		},
		{
			desc:    "identical records expires date",
			record1: FullRecord{Record: Record{ExpiresAt: &date}},
			record2: FullRecord{Record: Record{ExpiresAt: &date}},
			equal:   true,
		},
		{
			desc:    "expires date is nil in one record",
			record1: FullRecord{},
			record2: FullRecord{Record: Record{ExpiresAt: &date}},
			equal:   false,
		},
		{
			desc:    "expires date within margin of error",
			record1: FullRecord{Record: Record{ExpiresAt: &date}},
			record2: FullRecord{Record: Record{ExpiresAt: &dateSlightlyOff}},
			equal:   true,
		},
		{
			desc:    "records with differing expires date",
			record1: FullRecord{Record: Record{ExpiresAt: &date}},
			record2: FullRecord{Record: Record{ExpiresAt: &dateBeyondMargin}},
			equal:   false,
		},
		{
			desc:    "identical records invalidated date",
			record1: FullRecord{InvalidatedAt: date},
			record2: FullRecord{InvalidatedAt: date},
			equal:   true,
		},
		{
			desc:    "invalidated date is empty in one record",
			record1: FullRecord{},
			record2: FullRecord{InvalidatedAt: date},
			equal:   false,
		},
		{
			desc:    "invalidated date within margin of error",
			record1: FullRecord{InvalidatedAt: date},
			record2: FullRecord{InvalidatedAt: dateSlightlyOff},
			equal:   true,
		},
		{
			desc:    "records with differing invalidation date",
			record1: FullRecord{InvalidatedAt: date},
			record2: FullRecord{InvalidatedAt: dateBeyondMargin},
			equal:   false,
		},
		{
			desc:    "differing byte data",
			record1: FullRecord{Record: Record{MacaroonHead: []byte{'t'}}},
			record2: FullRecord{Record: Record{MacaroonHead: []byte{'z'}}},
			equal:   false,
		},
	}
	for _, test := range tests {
		if test.equal {
			require.True(t, test.record1.EqualWithinDuration(test.record2, margin), test.desc)
			require.True(t, test.record2.EqualWithinDuration(test.record1, margin), test.desc)
		} else {
			require.False(t, test.record1.EqualWithinDuration(test.record2, margin), test.desc)
			require.False(t, test.record2.EqualWithinDuration(test.record1, margin), test.desc)
		}
	}
}
