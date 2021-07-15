// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/storj/minio/cmd/logger/message/log"
	"go.uber.org/zap"
)

var accessRegexp = regexp.MustCompile("/access/.*\"")

// MinioSystemLogTarget is used for receiving system error messages from minio.
type MinioSystemLogTarget struct {
	log *zap.Logger
}

// NewMinioSystemLogTarget returns a new MinioSystemLogTarget.
func NewMinioSystemLogTarget(log *zap.Logger) *MinioSystemLogTarget {
	return &MinioSystemLogTarget{log: log}
}

// String is used by minio logger.Target but unused for our purposes.
func (lt *MinioSystemLogTarget) String() string { return "" }

// Endpoint is used by minio logger.Target but unused for our purposes.
func (lt *MinioSystemLogTarget) Endpoint() string { return "" }

// Validate is used by minio logger.Target but unused for our purposes.
func (lt *MinioSystemLogTarget) Validate() error { return nil }

// Send is called by minio whenever it logs an unexpected error, such as an
// internal server error that isn't mapped to a minio response. A system error
// in minio is defined as not having request information, as it occurs early
// in the request. An example of a system error is the IAM store in minio
// failing to retrieve a user, so in our case not being able to contact the
// auth service. We deliberately don't use this facility to log request scoped
// logs, like for specific handler (e.g. ListBuckets) errors, as those are
// handled separately in LogResponsesNoPaths().
func (lt *MinioSystemLogTarget) Send(e interface{}, errKind string) error {
	entry, ok := e.(log.Entry)
	if !ok {
		return fmt.Errorf("unexpected log entry structure %#v", e)
	}

	if entry.API == nil || entry.Trace == nil {
		return errors.New("log entry missing expected API and Trace fields")
	}

	if entry.API.Name != "SYSTEM" {
		return nil
	}

	// avoid logging access keys from errors, e.g.
	// "Get \"http://localhost:8000/v1/access/12345\": dial tcp ..."
	msg := entry.Trace.Message
	msg = accessRegexp.ReplaceAllString(msg, "[...]\"")

	mon.Event("gmt_unmapped_error",
		monkit.NewSeriesTag("api", "SYSTEM"),
		monkit.NewSeriesTag("error", msg))

	lt.log.Error("system", zap.String("error", msg))

	return nil
}
