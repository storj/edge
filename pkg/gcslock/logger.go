// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package gcslock

// Logger is the most basic set of what's needed for Mutex to log state.
type Logger interface {
	Infof(template string, args ...interface{})
	Errorf(template string, args ...interface{})
}

type wrappedLogger struct {
	logger Logger
}

var _ Logger = (*wrappedLogger)(nil)

func (w *wrappedLogger) Infof(template string, args ...interface{}) {
	if w.logger != nil {
		w.logger.Infof(template, args...)
	}
}

func (w *wrappedLogger) Errorf(template string, args ...interface{}) {
	if w.logger != nil {
		w.logger.Errorf(template, args...)
	}
}
