// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

//go:generate go test -run TestConfigLock -generate-config-lock

package main_test

import (
	"testing"

	"storj.io/gateway-mt/cmd/internal/testconfiglock"
)

func TestConfigLock(t *testing.T) {
	testconfiglock.Check(t, "gateway-mt")
}
