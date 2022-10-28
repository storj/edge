// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package gcslock

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zeebo/errs"
)

func TestWrappedLogger(t *testing.T) {
	require.NotPanics(t, func() {
		w := wrappedLogger{
			logger: nil,
		}
		w.Errorf("test 1: %v", errs.New("test 2"))
		w.Infof("another log line: %d", 123456789)
	})
}
