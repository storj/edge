// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package objectmap

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestIPDB_GetIPInfos(t *testing.T) {
	ctx := context.Background()
	mockReader := &MockReader{}

	tests := []struct {
		name        string
		reader      *MockReader
		ipAddress   string
		expected    *IPInfo
		expectedErr bool
	}{
		{"invalid IP", mockReader, "999.999.999.999", nil, true},
		{"invalid (IP:PORT)", mockReader, "999.999.999.999:42", nil, true},
		{"valid IP found geolocation", mockReader, "172.146.10.1", mockIPInfo(-19.456, 20.123), false},
		{"valid (IP:PORT) found geolocation", mockReader, "172.146.10.1:4545", mockIPInfo(-19.456, 20.123), false},
		{"valid IP geolocation not found", mockReader, "1.1.1.1", &IPInfo{}, true},
		{"valid (IP:PORT) geolocation not found", mockReader, "1.1.1.1:1000", &IPInfo{}, true},
	}
	for _, tt := range tests {
		mapper := NewIPDB(tt.reader)
		testCase := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := mapper.GetIPInfos(ctx, testCase.ipAddress)

			if testCase.expectedErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.EqualValues(t, testCase.expected, got)
			require.Equal(t, 1, len(mapper.cachedIPs))
		})
	}
}

func TestIPDB_GetIPInfos_Concurrent(t *testing.T) {
	ctx := context.Background()

	mockReader := &MockReader{}
	mapper := NewIPDB(mockReader)

	ips := [10]string{
		"172.146.10.1:4545",
		"172.146.10.2:4545",
		"172.146.10.3:4545",
		"172.146.10.4:4545",
		"172.146.10.5:4545",
		"172.146.10.6:4545",
		"172.146.10.7:4545",
		"172.146.10.8:4545",
		"172.146.10.9:4545",
		"172.146.10.10:4545",
	}

	ipv6addresses := [5]string{
		"2001:db8:a0b:12f0::1",
		"2001:db8:0:1:1:1:1:1",
		"[2001:db8:a0b:12f0::1]:21",
		"2001:db8:a0b:12f0::1/64",
		"2001:db8:a0b:12f0::1%eth0",
	}

	group, _ := errgroup.WithContext(context.Background())

	for _, ip := range ips {
		ip := ip
		t.Run(ip, func(t *testing.T) {
			group.Go(func() error {
				ipInfo, err := mapper.GetIPInfos(ctx, ip)

				assert.NoError(t, err)
				assert.NotNil(t, ipInfo)
				return nil
			})
			group.Go(func() error {
				ipInfo, err := mapper.GetIPInfos(ctx, ip)

				assert.NoError(t, err)
				assert.NotNil(t, ipInfo)
				return nil
			})
		})
	}

	for _, ip := range ipv6addresses {
		ip := ip
		t.Run(ip, func(t *testing.T) {
			group.Go(func() error {
				ipInfo, err := mapper.GetIPInfos(ctx, ip)

				assert.Error(t, err)
				assert.Nil(t, ipInfo)
				return nil
			})
			group.Go(func() error {
				ipInfo, err := mapper.GetIPInfos(ctx, ip)

				assert.Error(t, err)
				assert.Nil(t, ipInfo)
				return nil
			})
		})
	}

	err := group.Wait()
	require.NoError(t, err)

	require.Equal(t, 10, len(mapper.cachedIPs))
}
