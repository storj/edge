// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

//go:build go1.18
// +build go1.18

package badgerauth

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"

	"storj.io/gateway-mt/pkg/auth/authdb"
	"storj.io/gateway-mt/pkg/auth/badgerauth/pb"
)

func FuzzParseReplicationLogEntry(f *testing.F) {
	filledKeyHash := authdb.KeyHash{}

	// Add some cases to the seed corpus. They will also serve as normal test
	// cases when not fuzzing.
	for _, s := range [...]struct {
		id         []byte
		clockValue uint64
		keyHash    []byte
		state      int32
	}{
		{
			id:         []byte("test"),
			clockValue: 12345,
			keyHash:    []byte{'t', 'e', 's', 't'},
			state:      int32(pb.Record_CREATED),
		},
		{
			id:         []byte("fuzz!!1"),
			clockValue: 67890,
			keyHash:    []byte{'f', 'u', 'z', 'z'},
			state:      int32(pb.Record_INVALIDATED),
		},
		{
			id: []byte{}, // everything is empty
		},
		{
			id:         []byte("a bit longer ID"),
			clockValue: math.MaxUint64,
			keyHash:    filledKeyHash[:],
			state:      math.MaxInt32,
		},
	} {
		f.Add(s.id, s.clockValue, s.keyHash, s.state)
	}

	f.Fuzz(func(t *testing.T, id []byte, clockValue uint64, keyHashBytes []byte, state int32) {
		// keyHashBytes might be longer than 32 bytes while fuzzing, but copy
		// will fill out keyHash to at most that.
		var keyHash authdb.KeyHash
		copy(keyHash[:], keyHashBytes)

		e := newReplicationLogEntry(id, clockValue, keyHash, pb.Record_State(state))
		assert.Len(t, e.Key, cap(e.Key)) // make sure we don't over-allocate

		parsedID, parsedClockValue, parsedKeyHash, parsedState := parseReplicationLogEntry(e.Key)
		assert.Equal(t, id, parsedID)
		assert.Equal(t, clockValue, parsedClockValue)
		assert.Equal(t, keyHash, parsedKeyHash)
		assert.Equal(t, pb.Record_State(state), parsedState)
	})
}
