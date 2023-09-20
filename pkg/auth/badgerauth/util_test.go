// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"storj.io/common/testcontext"
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

func TestMarshalLogObjectCorrectness(t *testing.T) {
	t.Parallel()

	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	observedZapCore, observedLogs := observer.New(zap.InfoLevel)
	observedLogger := zap.New(observedZapCore)
	defer ctx.Check(observedLogger.Sync)

	clocks := make(clocksLogObject)
	clocks["app11"] = 123
	clocks["app12"] = 456
	clocks["app21"] = 789
	clocks["app22"] = 999999
	clocks["app31"] = 0

	observedLogger.Info("test", zap.Object("clocks", clocks))

	filter := observedLogs.FilterLevelExact(zap.InfoLevel)
	filter = filter.FilterMessage("test")
	filter = filter.FilterFieldKey("clocks")

	require.Equal(t, 1, filter.Len())

	assert.EqualValues(t, map[string]uint64{
		"app11": 123,
		"app12": 456,
		"app21": 789,
		"app22": 999999,
		"app31": 0,
	}, filter.All()[0].Context[0].Interface)
}
