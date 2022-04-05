// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

//go:build go1.18
// +build go1.18

package badgerauth

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"storj.io/gateway-mt/pkg/auth/authdb"
	"storj.io/gateway-mt/pkg/auth/badgerauth/pb"
)

func FuzzParsingReplicationLogEntry(f *testing.F) {
	// Add some cases to the seed corpus. They will also serve as normal test cases when not fuzzing.
	f.Add([]byte{}, uint64(0), []byte{}, int32(0))
	f.Add([]byte("test"), uint64(12345), []byte{'t', 'e', 's', 't'}, int32(pb.Record_CREATED))
	f.Add([]byte("fuzz!!1"), uint64(67890), []byte{'f', 'u', 'z', 'z'}, int32(pb.Record_CREATED))

	zeroKeyHash := authdb.KeyHash{}
	f.Add([]byte("a bit longer ID"), uint64(math.MaxUint64), zeroKeyHash[:], int32(math.MaxInt32))

	f.Fuzz(func(t *testing.T, idBytes []byte, clockValue uint64, keyHashBytes []byte, state int32) {
		id := NodeID(idBytes)
		clock := Clock(clockValue)
		// keyHashBytes might be longer than 32 bytes while fuzzing, but copy
		// will fill out keyHash to at most that.
		var keyHash authdb.KeyHash
		copy(keyHash[:], keyHashBytes)

		e1 := ReplicationLogEntry{
			ID:      id,
			Clock:   clock,
			KeyHash: keyHash,
			State:   pb.Record_State(state),
		}

		assert.Len(t, e1.Bytes(), cap(e1.Bytes())) // make sure we don't over-allocate

		var e2 ReplicationLogEntry
		require.NoError(t, e2.SetBytes(e1.Bytes()))

		assert.Equal(t, e1, e2)
	})
}
