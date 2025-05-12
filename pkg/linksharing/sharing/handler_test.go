// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCompareHosts(t *testing.T) {
	same := [][2]string{
		{"website.test", "website.test"},
		{"website.test:443", "website.test"},
		{"website.test:443", "website.test:443"},
		{"website.test:443", "website.test:880"},
		{"192.168.0.1:443", "192.168.0.1:880"},
		{"[::1]:443", "[::1]:880"},
	}
	for _, test := range same {
		result, err := compareHosts(test[0], test[1])
		assert.NoError(t, err)
		assert.True(t, result)
	}

	notsame := [][2]string{
		{"website.test:443", "site.test:443"},
		{"website.test", "site.test"},
		{"[::1]:443", "[::2]:880"},
	}
	for _, test := range notsame {
		result, err := compareHosts(test[0], test[1])
		assert.NoError(t, err)
		assert.False(t, result)
	}
}
