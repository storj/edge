// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package httplog

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// StatusLevel takes an HTTP status and returns an appropriate log level.
func StatusLevel(status int) zapcore.Level {
	switch {
	case status == 501:
		return zap.WarnLevel
	case status >= 500:
		return zap.ErrorLevel
	default:
		return zap.DebugLevel
	}
}
