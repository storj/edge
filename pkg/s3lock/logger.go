// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package s3lock

// Logger is the most basic set of what's needed for Mutex to log state.
type Logger interface {
	Infof(template string, args ...any)
	Errorf(template string, args ...any)
}

type wrappedLogger struct {
	logger Logger
}

var _ Logger = (*wrappedLogger)(nil)

func (w *wrappedLogger) Infof(template string, args ...any) {
	if w.logger != nil {
		w.logger.Infof(template, args...)
	}
}

func (w *wrappedLogger) Errorf(template string, args ...any) {
	if w.logger != nil {
		w.logger.Errorf(template, args...)
	}
}
