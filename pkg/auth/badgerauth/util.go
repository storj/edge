// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauth

import (
	"time"

	"go.uber.org/zap"

	"storj.io/gateway-mt/pkg/auth/badgerauth/pb"
)

// timestampToTime converts Unix time to *time.Time. It checks whether the
// supplied number of seconds is greater than 0 and returns nil *time.Time
// otherwise.
func timestampToTime(sec int64) *time.Time {
	if sec > 0 {
		t := time.Unix(sec, 0)
		return &t
	}
	return nil
}

// timeToTimestamp converts t to Unix time. It returns 0 if t is nil.
func timeToTimestamp(t *time.Time) int64 {
	if t != nil {
		return t.Unix()
	}
	return 0
}

func recordsEqual(a, b *pb.Record) bool {
	return pb.Equal(a, b)
}

// badgerLogger wraps zap's SugaredLogger, so it's possible to use it as badger's Logger.
type badgerLogger struct {
	*zap.SugaredLogger
}

// Warningf wraps zap's Warnf.
func (l badgerLogger) Warningf(format string, v ...interface{}) {
	l.Warnf(format, v...)
}
