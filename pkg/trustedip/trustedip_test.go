// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package trustedip

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetClientIP(t *testing.T) {
	testCases := []struct {
		desc string
		l    List
		r    *http.Request
		ip   string
	}{
		{
			desc: "Trusted IP 'Forwarded' single 'for'",
			l:    NewListTrustIPs("192.168.5.2", "10.5.2.23"),
			r: &http.Request{
				RemoteAddr: "10.5.2.23",
				Header:     map[string][]string{"Forwarded": {"for=172.17.5.10"}},
			},
			ip: "172.17.5.10",
		},
		{
			desc: "Trusted IP 'Forwarded' multiple 'for'",
			l:    NewListTrustIPs("192.168.5.2", "10.5.2.23"),
			r: &http.Request{
				RemoteAddr: "192.168.5.2",
				Header: map[string][]string{
					"Forwarded": {"for=172.31.254.250,for=172.17.5.10"},
				},
			},
			ip: "172.31.254.250",
		},
		{
			desc: "Trusted IP 'Forwarded' multiple 'for' with space after comma",
			l:    NewListTrustIPs("10.5.2.23"),
			r: &http.Request{
				RemoteAddr: "10.5.2.23",
				Header: map[string][]string{
					"Forwarded": {"for=192.168.5.250, for=172.17.5.10"},
				},
			},
			ip: "192.168.5.250",
		},
		{
			desc: "Trusted IP 'Forwarded' multiple 'for' with other pairs",
			l:    NewListTrustIPs("192.168.5.2", "10.5.2.23", "172.20.20.20"),
			r: &http.Request{
				RemoteAddr: "172.20.20.20",
				Header: map[string][]string{
					"Forwarded": {
						"by=storj;for=172.31.254.15,for=172.17.5.10;host=example.test;proto=https",
						"for=172.28.15.15",
					},
				},
			},
			ip: "172.31.254.15",
		},
		{
			desc: "Trusted IP 'X-Forwarded-For' single IP",
			l:    NewListTrustIPs("192.168.50.2", "10.5.2.23"),
			r: &http.Request{
				RemoteAddr: "192.168.50.2",
				Header:     map[string][]string{"X-Forwarded-For": {"172.31.254.80"}},
			},
			ip: "172.31.254.80",
		},
		{
			desc: "Trusted IP 'X-Forwarded-For' multiple IPs",
			l:    NewListTrustIPs("10.5.2.23", "192.168.50.2"),
			r: &http.Request{
				RemoteAddr: "192.168.50.2",
				Header: map[string][]string{
					"X-Forwarded-For": {"172.28.254.80, 192.168.80.25"},
				},
			},
			ip: "172.28.254.80",
		},
		{
			desc: "Trusted IP 'X-Real-Ip'",
			l:    NewListTrustIPs("192.168.50.2"),
			r: &http.Request{
				RemoteAddr: "192.168.50.2",
				Header:     map[string][]string{"X-Real-Ip": {"172.31.254.85"}},
			},
			ip: "172.31.254.85",
		},
		{
			desc: "Trusted IP no headers",
			l:    NewListTrustIPs("192.168.50.60", "10.5.2.23"),
			r: &http.Request{
				RemoteAddr: "192.168.50.60",
			},
			ip: "192.168.50.60",
		},
		{
			desc: "Trusted IP multiple headers",
			l:    NewListTrustIPs("10.5.2.23"),
			r: &http.Request{
				RemoteAddr: "10.5.2.23",
				Header: map[string][]string{
					"X-Forwarded-For": {"172.28.254.80, 192.168.80.25"},
					"Forwarded":       {"for=192.168.5.250, for=172.17.5.10"},
				},
			},
			ip: "192.168.5.250",
		},
		{
			desc: "Untrusted IP",
			l:    NewListTrustIPs("192.168.50.2", "10.5.2.23"),
			r: &http.Request{
				RemoteAddr: "192.168.100.15",
				Header:     map[string][]string{"X-Forwarded-For": {"172.31.254.80"}},
			},
			ip: "192.168.100.15",
		},
		{
			desc: "Untrusted any IP",
			l:    NewListUntrustAll(),
			r: &http.Request{
				RemoteAddr: "192.168.135.80:6968",
				Header: map[string][]string{
					"X-Forwarded-For": {"172.28.254.80, 192.168.80.25"},
					"Forwarded":       {"for=192.168.5.250, for=172.17.5.10"},
				},
			},
			ip: "192.168.135.80",
		},
	}

	for _, tC := range testCases {
		tC := tC
		t.Run(tC.desc, func(t *testing.T) {
			ip := GetClientIP(tC.l, tC.r)
			assert.Equal(t, tC.ip, ip)
		})
	}
}
