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
	// Add some cases to the seed corpus. They will also serve as normal test cases when not fuzzing.
	f.Add([]byte{}, uint64(0), []byte{}, int32(0))
	f.Add([]byte("test"), uint64(12345), []byte{'t', 'e', 's', 't'}, int32(pb.Record_CREATED))
	f.Add([]byte("fuzz!!1"), uint64(67890), []byte{'f', 'u', 'z', 'z'}, int32(pb.Record_INVALIDATED))

	zeroKeyHash := authdb.KeyHash{}
	f.Add([]byte("a bit longer ID"), uint64(math.MaxUint64), zeroKeyHash[:], int32(math.MaxInt32))

	f.Fuzz(func(t *testing.T, idBytes []byte, clockValue uint64, keyHashBytes []byte, state int32) {
		id := NodeID(idBytes)
		clock := Clock(clockValue)
		// keyHashBytes might be longer than 32 bytes while fuzzing, but copy
		// will fill out keyHash to at most that.
		var keyHash authdb.KeyHash
		copy(keyHash[:], keyHashBytes)

		e := newReplicationLogEntry(id, clock, keyHash, pb.Record_State(state))
		assert.Len(t, e.Key, cap(e.Key)) // make sure we don't over-allocate

		parsedID, parsedClock, parsedKeyHash, parsedState := parseReplicationLogEntry(e.Key)
		assert.Equal(t, id, parsedID)
		assert.Equal(t, clock, parsedClock)
		assert.Equal(t, keyHash, parsedKeyHash)
		assert.Equal(t, pb.Record_State(state), parsedState)
	})
}
