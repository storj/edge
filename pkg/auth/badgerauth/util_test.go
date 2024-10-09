// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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
