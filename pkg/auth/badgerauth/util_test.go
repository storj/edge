// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"storj.io/gateway-mt/pkg/auth/badgerauth/pb"
)

func TestTimestampToTime(t *testing.T) {
	t.Parallel()

	// Construct current time used in this test so that it is stripped of the
	// number of nanoseconds and the monotonic clock reading.
	now := time.Unix(time.Now().Unix(), 0)
	assert.Equal(t, (*time.Time)(nil), timestampToTime(0))
	assert.Equal(t, &now, timestampToTime(now.Unix()))
}

func TestTimeToTimestamp(t *testing.T) {
	t.Parallel()

	now := time.Now()
	assert.EqualValues(t, 0, timeToTimestamp(nil))
	assert.Equal(t, now.Unix(), timeToTimestamp(&now))
}

func TestRecordsEqual(t *testing.T) {
	t.Parallel()

	assert.True(t, recordsEqual(&pb.Record{}, &pb.Record{}))

	r1 := pb.Record{
		CreatedAtUnix:        1,
		Public:               true,
		SatelliteAddress:     "3",
		MacaroonHead:         []byte{4},
		ExpiresAtUnix:        5,
		EncryptedSecretKey:   []byte{6},
		EncryptedAccessGrant: []byte{7},
		InvalidationReason:   "8",
		InvalidatedAtUnix:    9,
		State:                pb.Record_CREATED,
	}
	r2 := pb.Record{
		CreatedAtUnix:        1,
		Public:               true,
		SatelliteAddress:     "3",
		MacaroonHead:         []byte{4},
		ExpiresAtUnix:        5,
		EncryptedSecretKey:   []byte{6},
		EncryptedAccessGrant: []byte{7},
		InvalidationReason:   "8",
		InvalidatedAtUnix:    9,
		State:                pb.Record_CREATED,
	}
	assert.True(t, recordsEqual(&r1, &r2))

	r2.ExpiresAtUnix = time.Now().Unix()
	assert.False(t, recordsEqual(&r1, &r2))
}
