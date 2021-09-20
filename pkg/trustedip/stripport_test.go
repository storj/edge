// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package trustedip

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStripPort(t *testing.T) {
	testCases := []struct {
		desc string
		addr string
		exp  string
	}{
		{
			desc: "hostname no port",
			addr: "storj.test",
			exp:  "storj.test",
		},
		{
			desc: "hostname port",
			addr: "storj.test:1234",
			exp:  "storj.test",
		},
		{
			desc: "hostname invalid",
			addr: "storj:test:123:",
			exp:  "storj:test:123:",
		},
		{
			desc: "IPv4 no port",
			addr: "192.168.1.78",
			exp:  "192.168.1.78",
		},
		{
			desc: "IPv4 port",
			addr: "192.168.7.69:7888",
			exp:  "192.168.7.69",
		},
		{
			desc: "IPv4 invalid",
			addr: "1985:5849.15.15:8080:",
			exp:  "1985:5849.15.15:8080:",
		},
		{
			desc: "IPv6 no port",
			addr: "6934:9e20:e075:a5f6:c8d2:21d1:124d:94b7",
			exp:  "6934:9e20:e075:a5f6:c8d2:21d1:124d:94b7",
		},
		{
			desc: "IPv6 port",
			addr: "[6934:9e20:e075:a5f6:c8d2:21d1:124d:94b7]:9898",
			exp:  "6934:9e20:e075:a5f6:c8d2:21d1:124d:94b7",
		},
		{
			desc: "IPv6 invalid not closing bracket",
			addr: "[6934:9e20:e075:a5f6:c8d2:21d1:124d:94b7:9898",
			exp:  "6934:9e20:e075:a5f6:c8d2:21d1:124d:94b",
		},
		{
			desc: "IPv6 invalid port without brackets",
			addr: "6934:9e20:e075:a5f6:c8d2:21d1:124d:94b7:9898",
			exp:  "6934:9e20:e075:a5f6:c8d2:21d1:124d:94b7:9898",
		},
		{
			desc: "IPv6 invalid brackets no port",
			addr: "[6934:9e20:e075:a5f6:c8d2:21d1:124d:94b7]",
			exp:  "6934:9e20:e075:a5f6:c8d2:21d1:124",
		},
		{
			desc: "empty address",
			addr: "",
			exp:  "",
		},
		{
			desc: "invalid address bracket",
			addr: "[",
			exp:  "[",
		},
		{
			desc: "invalid address bracket-colon",
			addr: "[:",
			exp:  "[:",
		},
		{
			desc: "invalid address brackets",
			addr: "[]",
			exp:  "[]",
		},
		{
			desc: "invalid address colon",
			addr: ":",
			exp:  "",
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			host := stripPort(tC.addr)
			require.Equal(t, tC.exp, host)
		})
	}
}
