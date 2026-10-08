// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package gwlog

import (
	"context"
	"strings"

	"storj.io/minio/cmd/logger"
)

type contextKeyType string

const contextKey contextKeyType = "gwlog"

// Log is a wrapper around logger.ReqInfo for keeping track of gateway request info.
// It is primarily useful for logging middleware using a separate context value than
// what minio uses, which we can't get at due to the way it creates new context when
// each gateway handler is called.
type Log struct {
	*logger.ReqInfo
}

// WithContext returns a copy of the parent context with Log value.
func (log *Log) WithContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, contextKey, log)
}

// TagValue returns the value for the given key in tags, if it exists.
// The returned value is coerced to valid UTF-8, since tag values may
// originate from untrusted, non-UTF-8 input (e.g. object keys embedded
// in error messages), and consumers of this value (access logs, zap
// logging, and eventkit's events pipeline) expect valid UTF-8 strings.
func (log *Log) TagValue(key string) string {
	for _, tag := range log.GetTags() {
		if tag.Key == key {
			if v, ok := tag.Val.(string); ok {
				return strings.ToValidUTF8(v, "�")
			}
		}
	}
	return ""
}

// New returns a new Log.
func New() *Log {
	l := Log{&logger.ReqInfo{}}
	l.API = "unknown"
	return &l
}

// FromContext gets a Log from context.
func FromContext(ctx context.Context) (*Log, bool) {
	l, ok := ctx.Value(contextKey).(*Log)
	return l, ok
}
