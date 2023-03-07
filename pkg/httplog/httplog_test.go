// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package httplog

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestStatusLevel(t *testing.T) {
	testCases := []struct {
		status        int
		expectedLevel zapcore.Level
	}{
		{
			status:        http.StatusOK,
			expectedLevel: zap.DebugLevel,
		},
		{
			status:        http.StatusCreated,
			expectedLevel: zap.DebugLevel,
		},
		{
			status:        http.StatusMultipleChoices,
			expectedLevel: zap.DebugLevel,
		},
		{
			status:        http.StatusPermanentRedirect,
			expectedLevel: zap.DebugLevel,
		},
		{
			status:        http.StatusBadRequest,
			expectedLevel: zap.InfoLevel,
		},
		{
			status:        http.StatusNotFound,
			expectedLevel: zap.InfoLevel,
		},
		{
			status:        http.StatusInternalServerError,
			expectedLevel: zap.ErrorLevel,
		},
		{
			status:        http.StatusBadGateway,
			expectedLevel: zap.ErrorLevel,
		},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(fmt.Sprintf("HTTP %d response logged as %s", tc.status, tc.expectedLevel), func(t *testing.T) {
			require.Equal(t, tc.expectedLevel, StatusLevel(tc.status))
		})
	}
}
