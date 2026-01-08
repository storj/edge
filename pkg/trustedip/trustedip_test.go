// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package trustedip_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"storj.io/edge/pkg/trustedip"
)

func TestGetClientIP(t *testing.T) {
	testCases := []struct {
		desc string
		l    trustedip.List
		r    *http.Request
		ip   string
	}{
		{
			desc: "Trusted IP (v4) 'X-Forwarded-For' single IP",
			l:    trustedip.NewList("192.168.50.2", "10.5.2.23"),
			r: &http.Request{
				RemoteAddr: "192.168.50.2",
				Header:     map[string][]string{"X-Forwarded-For": {"172.31.254.80"}},
			},
			ip: "172.31.254.80",
		},
		{
			desc: "Trusted IP (v6) 'X-Forwarded-For' single IP",
			l:    trustedip.NewList("8428:f6d:9d3d:82cf:7190:3c31:3326:8484", "10.5.2.23"),
			r: &http.Request{
				RemoteAddr: "[8428:f6d:9d3d:82cf:7190:3c31:3326:8484]:123",
				Header:     map[string][]string{"X-Forwarded-For": {"49d4:4f54:d2fa:4f5f:fe12:d3bf:d523:192c"}},
			},
			ip: "49d4:4f54:d2fa:4f5f:fe12:d3bf:d523:192c",
		},
		{
			desc: "Trusted IP (v4) 'X-Forwarded-For' multiple IPs",
			l:    trustedip.NewList("10.5.2.23", "192.168.50.2"),
			r: &http.Request{
				RemoteAddr: "192.168.50.2",
				Header: map[string][]string{
					"X-Forwarded-For": {"172.28.254.80, 192.168.80.25"},
				},
			},
			ip: "192.168.80.25",
		},
		{
			desc: "Trusted IP (v6) 'X-Forwarded-For' multiple IPs",
			l:    trustedip.NewList("49d4:4f54:d2fa:4f5f:fe12:d3bf:d523:192c", "192.168.50.2"),
			r: &http.Request{
				RemoteAddr: "49d4:4f54:d2fa:4f5f:fe12:d3bf:d523:192c",
				Header: map[string][]string{
					"X-Forwarded-For": {"6e11:d5a8:b04d:9416:1f51:5262:15bc:4be6, 8428:f6d:9d3d:82cf:7190:3c31:3326:8484"},
				},
			},
			ip: "8428:f6d:9d3d:82cf:7190:3c31:3326:8484",
		},
		{
			desc: "Trusted IP (v4) no headers",
			l:    trustedip.NewList("192.168.50.60", "10.5.2.23"),
			r: &http.Request{
				RemoteAddr: "192.168.50.60",
			},
			ip: "192.168.50.60",
		},
		{
			desc: "Trusted IP (v6) no headers",
			l:    trustedip.NewList("192.168.50.60", "8428:f6d:9d3d:82cf:7190:3c31:3326:8484"),
			r: &http.Request{
				RemoteAddr: "[8428:f6d:9d3d:82cf:7190:3c31:3326:8484]:7894",
			},
			ip: "8428:f6d:9d3d:82cf:7190:3c31:3326:8484",
		},
		{
			desc: "Trusted IP (v4) multiple headers",
			l:    trustedip.NewList("10.5.2.23"),
			r: &http.Request{
				RemoteAddr: "10.5.2.23",
				Header: map[string][]string{
					"X-Forwarded-For": {"172.28.254.80, 192.168.80.25"},
					"Forwarded":       {"for=192.168.5.250, for=172.17.5.10"},
				},
			},
			ip: "192.168.80.25",
		},
		{
			desc: "Trusted IP (v6) multiple headers",
			l:    trustedip.NewList("8428:f6d:9d3d:82cf:7190:3c31:3326:8484"),
			r: &http.Request{
				RemoteAddr: "8428:f6d:9d3d:82cf:7190:3c31:3326:8484",
				Header: map[string][]string{
					"X-Forwarded-For": {"172.28.254.80, 192.168.80.25"},
					"Forwarded":       {"for=49d4:4f54:d2fa:4f5f:fe12:d3bf:d523:192c, for=172.17.5.10"},
				},
			},
			ip: "192.168.80.25",
		},
		{
			desc: "Untrusted IP (v4)",
			l:    trustedip.NewList("192.168.50.2", "10.5.2.23"),
			r: &http.Request{
				RemoteAddr: "192.168.100.15",
				Header:     map[string][]string{"X-Forwarded-For": {"172.31.254.80"}},
			},
			ip: "192.168.100.15",
		},
		{
			desc: "Untrusted IP (v6)",
			l:    trustedip.NewList("49d4:4f54:d2fa:4f5f:fe12:d3bf:d523:192c", "10.5.2.23"),
			r: &http.Request{
				RemoteAddr: "8428:f6d:9d3d:82cf:7190:3c31:3326:8484",
				Header:     map[string][]string{"X-Forwarded-For": {"172.31.254.80"}},
			},
			ip: "8428:f6d:9d3d:82cf:7190:3c31:3326:8484",
		},
		{
			desc: "Untrusted any IP (v4)",
			l:    trustedip.NewListUntrustAll(),
			r: &http.Request{
				RemoteAddr: "192.168.135.80:6968",
				Header: map[string][]string{
					"X-Forwarded-For": {"172.28.254.80, 192.168.80.25"},
					"Forwarded":       {"for=192.168.5.250, for=172.17.5.10"},
				},
			},
			ip: "192.168.135.80",
		},
		{
			desc: "Untrusted any IP (v6)",
			l:    trustedip.NewListUntrustAll(),
			r: &http.Request{
				RemoteAddr: "[6e11:d5a8:b04d:9416:1f51:5262:15bc:4be6]:5458",
				Header: map[string][]string{
					"X-Forwarded-For": {"172.28.254.80, 192.168.80.25"},
					"Forwarded":       {"for=192.168.5.250, for=172.17.5.10"},
				},
			},
			ip: "6e11:d5a8:b04d:9416:1f51:5262:15bc:4be6",
		},
	}

	for _, tC := range testCases {
		tC := tC
		t.Run(tC.desc, func(t *testing.T) {
			ip := trustedip.GetClientIP(tC.l, tC.r)
			assert.Equal(t, tC.ip, ip)
		})
	}
}

func TestGetClientIPFromHeaders(t *testing.T) {
	testCases := []struct {
		desc string
		r    *http.Request
		ip   string
		ok   bool
	}{
		{
			desc: "'X-Forwarded-For' single IP",
			r: &http.Request{
				RemoteAddr: "192.168.50.2",
				Header:     map[string][]string{"X-Forwarded-For": {"172.31.254.80"}},
			},
			ip: "172.31.254.80",
			ok: true,
		},
		{
			desc: "'X-Forwarded-For' multiple IPs",
			r: &http.Request{
				RemoteAddr: "192.168.50.2",
				Header: map[string][]string{
					"X-Forwarded-For": {"172.28.254.80, 192.168.80.25"},
				},
			},
			ip: "192.168.80.25",
			ok: true,
		},
		{
			desc: "multiple headers",
			r: &http.Request{
				RemoteAddr: "10.5.2.23",
				Header: map[string][]string{
					"X-Forwarded-For": {"172.28.254.80, 192.168.80.25"},
					"Forwarded":       {"for=192.168.5.250, for=172.17.5.10"},
					"X-Real-Ip":       {"172.31.254.85"},
				},
			},
			ip: "192.168.80.25",
			ok: true,
		},
		{
			desc: "no headers",
			r: &http.Request{
				RemoteAddr: "192.168.50.60",
			},
			ok: false,
		},
	}

	for _, tC := range testCases {
		tC := tC
		t.Run(tC.desc, func(t *testing.T) {
			ip, ok := trustedip.GetIPFromHeaders(tC.r.Header)
			if !tC.ok {
				assert.Equal(t, tC.ok, ok, "OK")
				return
			}

			assert.Equal(t, tC.ip, ip)
			assert.Equal(t, tC.ok, ok)
		})
	}
}
