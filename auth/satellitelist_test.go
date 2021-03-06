// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package auth

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"storj.io/common/testcontext"
)

func TestLoadSatelliteAddresses(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	withIds := []string{
		"12EayRS2V1kEsWESU9QMRseFhdxYxKicsiFmxrsLZHeLUtdps3S@us-central-1.tardigrade.io:7777",
		"12L9ZFwhzVpuEKMUNUqkaTLGzwY9G24tbiigLiXpmZWKwmcNDDs@europe-west-1.tardigrade.io:7777",
		"121RTSDpyNZVcEU84Ticf2L1ntiuUimbWgfATz21tuvgk3vzoA6@asia-east-1.tardigrade.io:7777",
		"1wFTAgs9DP5RSnCqKV1eLf6N9wtk4EAtmN5DpSxcs8EjT69tGE@saltlake.tardigrade.io:7777",
		"12rfG3sh9NCWiX3ivPjq2HtdLmbqCrvHVEzJubnzFzosMuawymB@europe-north-1.tardigrade.io:7777",
		"12tRQrMTWUWwzwGh18i7Fqs67kmdhH9t6aToeiwbo5mfS2rUmo@35.192.11.148:7777",
	}
	withoutIds := []string{
		"us-central-1.tardigrade.io:7777",
		"europe-west-1.tardigrade.io:7777",
		"asia-east-1.tardigrade.io:7777",
		"saltlake.tardigrade.io:7777",
		"europe-north-1.tardigrade.io:7777",
		"35.192.11.148:7777", // IP-based address for good measure
	}

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, line := range withIds {
			fmt.Fprintln(w, line)
		}
	}))
	defer testServer.Close()

	testFile := ctx.File("tempSatFile")
	require.NoError(t, ioutil.WriteFile(testFile, []byte(strings.Join(withoutIds, "\r\n")), 0644))

	tests := []struct {
		input     []string
		isDynamic bool
		hasErr    bool
	}{
		{withIds, false, false},
		{withoutIds, false, false},
		{[]string{testServer.URL}, true, false},
		{[]string{testFile}, true, false},
		{append(append(withIds, withoutIds...), testServer.URL), true, false},
		{[]string{"nonsense"}, false, true},
		{[]string{"garbage:input"}, false, true},
	}

	expected := make(map[string]struct{})
	for _, a := range withoutIds {
		expected[a] = struct{}{}
	}

	for i, tc := range tests {
		satList, isDynamic, err := LoadSatelliteAddresses(ctx, tc.input)
		require.Equal(t, tc.hasErr, err != nil, i)
		if !tc.hasErr {
			require.Equal(t, expected, satList, i)
			require.Equal(t, tc.isDynamic, isDynamic, i)
		}
	}
}
