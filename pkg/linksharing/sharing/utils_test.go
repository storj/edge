// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"fmt"
	"math/rand"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"storj.io/common/errs2"
	"storj.io/common/testcontext"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func randSleep() {
	time.Sleep(time.Duration(rand.Int31n(50)) * time.Microsecond)
}

func TestMutexGroup(t *testing.T) {
	defer testcontext.NewWithTimeout(t, time.Minute).Cleanup()

	var accesses errs2.Group

	var muGroup MutexGroup
	var counters [3]*int32
	totalCounter := new(int32)
	for lockNo := 0; lockNo < len(counters); lockNo++ {
		counters[lockNo] = new(int32)
		for workerNo := 0; workerNo < 10; workerNo++ {
			lockNo := lockNo
			accesses.Go(func() error {
				lockName := fmt.Sprint(lockNo)

				highwater := int32(0)

				for i := 0; i < 100; i++ {
					randSleep()
					err := func() error {
						unlock := muGroup.Lock(lockName)
						defer unlock()

						incr := atomic.AddInt32(counters[lockNo], 1)
						if incr != 1 {
							return fmt.Errorf("expected incr %v got %v;", 1, incr)
						}

						total := atomic.AddInt32(totalCounter, 1)
						if total > int32(len(counters)) {
							return fmt.Errorf("total %v > counters %v;", total, len(counters))
						}
						if total > highwater {
							highwater = total
						}
						randSleep()

						decr := atomic.AddInt32(counters[lockNo], -1)
						if decr != 0 {
							return fmt.Errorf("expected decr %v got %v;", 0, decr)
						}

						totalAfter := atomic.AddInt32(totalCounter, -1)
						if totalAfter < 0 {
							return fmt.Errorf("total was negative, got %v;", totalAfter)
						}

						return nil
					}()
					if err != nil {
						return err
					}
				}

				if highwater != int32(len(counters)) {
					return fmt.Errorf("highwater %v != len(counters) %v;", highwater, len(counters))
				}
				return nil
			})
		}
	}
	require.Empty(t, accesses.Wait())

	require.Equal(t, int32(0), *totalCounter)
	for lockNo := 0; lockNo < len(counters); lockNo++ {
		require.Equal(t, int32(0), *counters[lockNo])
	}
}

func TestGetClientIP(t *testing.T) {
	testCases := []struct {
		desc string
		tipl trustedIPsList
		r    *http.Request
		ip   string
	}{
		{
			desc: "Trusted IP 'Forwarded' single 'for'",
			tipl: newTrustedIPsListTrustIPs("192.168.5.2", "10.5.2.23"),
			r: &http.Request{
				RemoteAddr: "10.5.2.23",
				Header:     map[string][]string{"Forwarded": {"for=172.17.5.10"}},
			},
			ip: "172.17.5.10",
		},
		{
			desc: "Trusted IP 'Forwarded' multiple 'for'",
			tipl: newTrustedIPsListTrustIPs("192.168.5.2", "10.5.2.23"),
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
			tipl: newTrustedIPsListTrustIPs("10.5.2.23"),
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
			tipl: newTrustedIPsListTrustIPs("192.168.5.2", "10.5.2.23", "172.20.20.20"),
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
			tipl: newTrustedIPsListTrustIPs("192.168.50.2", "10.5.2.23"),
			r: &http.Request{
				RemoteAddr: "192.168.50.2",
				Header:     map[string][]string{"X-Forwarded-For": {"172.31.254.80"}},
			},
			ip: "172.31.254.80",
		},
		{
			desc: "Trusted IP 'X-Forwarded-For' multiple IPs",
			tipl: newTrustedIPsListTrustIPs("10.5.2.23", "192.168.50.2"),
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
			tipl: newTrustedIPsListTrustIPs("192.168.50.2"),
			r: &http.Request{
				RemoteAddr: "192.168.50.2",
				Header:     map[string][]string{"X-Real-Ip": {"172.31.254.85"}},
			},
			ip: "172.31.254.85",
		},
		{
			desc: "Trusted IP no headers",
			tipl: newTrustedIPsListTrustIPs("192.168.50.60", "10.5.2.23"),
			r: &http.Request{
				RemoteAddr: "192.168.50.60",
			},
			ip: "192.168.50.60",
		},
		{
			desc: "Trusted IP multiple headers",
			tipl: newTrustedIPsListTrustIPs("10.5.2.23"),
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
			tipl: newTrustedIPsListTrustIPs("192.168.50.2", "10.5.2.23"),
			r: &http.Request{
				RemoteAddr: "192.168.100.15",
				Header:     map[string][]string{"X-Forwarded-For": {"172.31.254.80"}},
			},
			ip: "192.168.100.15",
		},
		{
			desc: "Untrusted any IP",
			tipl: newTrustedIPsListUntrustAll(),
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
			ip := getClientIP(tC.tipl, tC.r)
			assert.Equal(t, tC.ip, ip)
		})
	}
}
