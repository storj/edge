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
	case status >= 500:
		return zap.ErrorLevel
	case status >= 400:
		return zap.InfoLevel
	default:
		return zap.DebugLevel
	}
}
