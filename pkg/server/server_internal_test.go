// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeduplicateDomains(t *testing.T) {
	test := func(input string, expected []string) {
		output := deduplicateDomains(input)
		sort.Strings(expected)
		sort.Strings(output)
		require.Equal(t, expected, output)
	}

	test("gateway.local,gateway.local", []string{"gateway.local"})
	test("gateway.local,*.gateway.local", []string{"gateway.local"})
	test("gateway.local,*.gateway.local,test.com,*.test.com", []string{"gateway.local", "test.com"})
	test("gateway.local,*.gateway.local,*.gateway2.local", []string{"gateway.local", "gateway2.local"})
}
