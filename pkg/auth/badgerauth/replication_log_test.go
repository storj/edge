// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

//go:build go1.18
// +build go1.18

package badgerauth

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"storj.io/gateway-mt/pkg/auth/authdb"
	"storj.io/gateway-mt/pkg/auth/badgerauth/pb"
)

func FuzzParsingReplicationLogEntry(f *testing.F) {
	// Add some cases to the seed corpus. They will also serve as normal test
	// cases when not fuzzing.
	f.Add([]byte{}, uint64(0), []byte{}, int32(0))
	f.Add([]byte("test"), uint64(12345), []byte{'t', 'e', 's', 't'}, int32(pb.Record_CREATED))
	f.Add([]byte("fuzz!!1"), uint64(67890), []byte{'f', 'u', 'z', 'z'}, int32(pb.Record_CREATED))

	zeroKeyHash := authdb.KeyHash{}
	f.Add([]byte("a bit longer ID"), uint64(math.MaxUint64), zeroKeyHash.Bytes(), int32(math.MaxInt32))

	f.Fuzz(func(t *testing.T, idBytes []byte, clockValue uint64, keyHashBytes []byte, state int32) {
		if len(idBytes) > lenNodeID {
			idBytes = idBytes[:lenNodeID]
		}

		var id NodeID
		require.NoError(t, id.SetBytes(idBytes))

		clock := Clock(clockValue)

		var keyHash authdb.KeyHash
		require.NoError(t, keyHash.SetBytes(keyHashBytes))

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

// FuzzMakeIterationStartKeyOrder and TestMakeIterationStartKey are a bit
// exhaustive, but what they test is important, so it's good to have them in
// case we would accidentally break something.
func FuzzMakeIterationStartKeyOrder(f *testing.F) {
	// Add some cases to the seed corpus. They will also serve as normal test
	// cases when not fuzzing.
	f.Add([]byte{}, uint64(0), uint64(0))
	f.Add([]byte("test1"), uint64(12345), uint64(67890))
	f.Add([]byte("eu1-1"), uint64(math.MaxUint64), uint64(1))

	f.Fuzz(func(t *testing.T, idBytes []byte, clockValue1, clockValue2 uint64) {
		if len(idBytes) > lenNodeID {
			idBytes = idBytes[:lenNodeID]
		}

		var id NodeID
		require.NoError(t, id.SetBytes(idBytes))

		clock1, clock2 := Clock(clockValue1), Clock(clockValue2)

		startKey1 := makeIterationStartKey(id, clock1)
		startKey2 := makeIterationStartKey(id, clock2)

		assert.Len(t, startKey1, cap(startKey1))
		assert.Len(t, startKey2, cap(startKey2))

		assert.Equal(t, clock1 > clock2, bytes.Compare(startKey1, startKey2) > 0)
	})
}

func TestMakeIterationStartKey(t *testing.T) {
	t.Parallel()

	id, clock := NodeID{'t', 'e', 's', 't'}, Clock(1234567890)

	got := makeIterationStartKey(id, clock)

	assert.Len(t, got, cap(got)) // make sure we don't over-allocate

	assert.True(t, bytes.HasPrefix(got, []byte(replicationLogPrefix)))
	got = got[lenReplicationLogPrefix:]
	assert.True(t, bytes.HasPrefix(got, id.Bytes()))
	got = got[len(id):]
	assert.True(t, bytes.HasPrefix(got, []byte(replicationLogEntrySeparator)))
	got = got[lenReplicationLogEntrySeparator:]

	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(clock))

	assert.True(t, bytes.HasPrefix(got, b[:]))
	got = got[8:]

	assert.Empty(t, got)
}
