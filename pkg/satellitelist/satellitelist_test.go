// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package satellitelist

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"storj.io/common/storj"
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

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, line := range withIds {
			fmt.Fprintln(w, line)
		}
	}))
	defer testServer.Close()

	testFile := ctx.File("tempSatFile")
	require.NoError(t, os.WriteFile(testFile, []byte(strings.Join(withIds, "\r\n")), 0644))

	tests := []struct {
		input     []string
		isDynamic bool
	}{
		{withIds, false},
		{[]string{testServer.URL}, true},
		{[]string{testFile}, true},
		{append(withIds, testServer.URL), true},
	}

	expected := make(map[storj.NodeURL]struct{})
	for _, a := range withIds {
		url, err := storj.ParseNodeURL(a)
		require.NoError(t, err)
		expected[url] = struct{}{}
	}

	for i, tc := range tests {
		satList, isDynamic, err := LoadSatelliteURLs(ctx, tc.input)
		require.NoError(t, err, i)
		require.Equal(t, expected, satList, i)
		require.Equal(t, tc.isDynamic, isDynamic, i)
	}
}

func TestLoadSatelliteAddresses_Invalid(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	for i, v := range []string{
		"nonsense",
		"garbage:input",
	} {
		_, _, err := LoadSatelliteURLs(ctx, []string{v})
		require.Error(t, err, i)
	}
}

func TestReadSatelliteList(t *testing.T) {
	validNodeURLs, err := storj.ParseNodeURLs("118UWpMCHzs6CvSgWd9BfFVjw5K9pZ" +
		"bJjkfZJexMtSkmKxvvAW@satellite.stefan-benten.de:7777,12EayRS2V1kEsWE" +
		"SU9QMRseFhdxYxKicsiFmxrsLZHeLUtdps3S@us1.storj.io:7777,12L9ZFwhzVpuE" +
		"KMUNUqkaTLGzwY9G24tbiigLiXpmZWKwmcNDDs@eu1.storj.io:7777,121RTSDpyNZ" +
		"VcEU84Ticf2L1ntiuUimbWgfATz21tuvgk3vzoA6@ap1.storj.io:7777,1wFTAgs9D" +
		"P5RSnCqKV1eLf6N9wtk4EAtmN5DpSxcs8EjT69tGE@saltlake.tardigrade.io:777" +
		"7,12rfG3sh9NCWiX3ivPjq2HtdLmbqCrvHVEzJubnzFzosMuawymB@europe-north-1" +
		".tardigrade.io:7777,12tRQrMTWUWwzwGh18i7Fqs67kmdhH9t6aToeiwbo5mfS2rU" +
		"mo@us2.storj.io:7777")
	require.NoError(t, err)

	tests := []struct {
		name               string
		input              []byte
		satellites         map[storj.NodeURL]struct{}
		expectedSatellites map[storj.NodeURL]struct{}
	}{
		{
			name:               "empty",
			satellites:         make(map[storj.NodeURL]struct{}),
			expectedSatellites: make(map[storj.NodeURL]struct{}),
		},
		{
			name: "comments only",
			input: []byte("# 118UWpMCHzs6CvSgWd9BfFVjw5K9pZbJjkfZJexMtSkmKxvv" +
				"AW@satellite.stefan-benten.de:7777\n#12L9ZFwhzVpuEKMUNUqkaTL" +
				"GzwY9G24tbiigLiXpmZWKwmcNDDs@eu1.storj.io:7777"),
			satellites:         make(map[storj.NodeURL]struct{}),
			expectedSatellites: make(map[storj.NodeURL]struct{}),
		},
		{
			name: "one satellite",
			input: []byte("118UWpMCHzs6CvSgWd9BfFVjw5K9pZbJjkfZJexMtSkmKxvvAW" +
				"@satellite.stefan-benten.de:7777"),
			satellites: make(map[storj.NodeURL]struct{}),
			expectedSatellites: map[storj.NodeURL]struct{}{
				validNodeURLs[0]: {},
			},
		},
		{
			name: "multiple satellites",
			input: []byte("12EayRS2V1kEsWESU9QMRseFhdxYxKicsiFmxrsLZHeLUtdps3" +
				"S@us1.storj.io:7777\n12L9ZFwhzVpuEKMUNUqkaTLGzwY9G24tbiigLiX" +
				"pmZWKwmcNDDs@eu1.storj.io:7777\n121RTSDpyNZVcEU84Ticf2L1ntiu" +
				"UimbWgfATz21tuvgk3vzoA6@ap1.storj.io:7777\n1wFTAgs9DP5RSnCqK" +
				"V1eLf6N9wtk4EAtmN5DpSxcs8EjT69tGE@saltlake.tardigrade.io:777" +
				"7\n12rfG3sh9NCWiX3ivPjq2HtdLmbqCrvHVEzJubnzFzosMuawymB@europ" +
				"e-north-1.tardigrade.io:7777\n12tRQrMTWUWwzwGh18i7Fqs67kmdhH" +
				"9t6aToeiwbo5mfS2rUmo@us2.storj.io:7777"),
			satellites: make(map[storj.NodeURL]struct{}),
			expectedSatellites: map[storj.NodeURL]struct{}{
				validNodeURLs[1]: {},
				validNodeURLs[2]: {},
				validNodeURLs[3]: {},
				validNodeURLs[4]: {},
				validNodeURLs[5]: {},
				validNodeURLs[6]: {},
			},
		},
		{
			name: "one satellite is commented-out",
			input: []byte("121RTSDpyNZVcEU84Ticf2L1ntiuUimbWgfATz21tuvgk3vzoA" +
				"6@ap1.storj.io:7777\n1wFTAgs9DP5RSnCqKV1eLf6N9wtk4EAtmN5DpSx" +
				"cs8EjT69tGE@saltlake.tardigrade.io:7777\n# 118UWpMCHzs6CvSgW" +
				"d9BfFVjw5K9pZbJjkfZJexMtSkmKxvvAW@satellite.stefan-benten.de" +
				":7777\n12rfG3sh9NCWiX3ivPjq2HtdLmbqCrvHVEzJubnzFzosMuawymB@e" +
				"urope-north-1.tardigrade.io:7777"),
			satellites: make(map[storj.NodeURL]struct{}),
			expectedSatellites: map[storj.NodeURL]struct{}{
				validNodeURLs[3]: {},
				validNodeURLs[4]: {},
				validNodeURLs[5]: {},
			},
		},
		{
			name: "multiple consecutive line breaks and comments, and whitespace here and there",
			input: []byte("# https://www.storj.io/dcs-satellites\n\n\t\t\t\n " +
				" \t   121RTSDpyNZVcEU84Ticf2L1ntiuUimbWgfATz21tuvgk3vzoA6@ap" +
				"1.storj.io:7777\n# 1wFTAgs9DP5RSnCqKV1eLf6N9wtk4EAtmN5DpSxcs" +
				"8EjT69tGE@saltlake.tardigrade.io:7777\n\n# 118UWpMCHzs6CvSgW" +
				"d9BfFVjw5K9pZbJjkfZJexMtSkmKxvvAW@satellite.stefan-benten.de" +
				":7777\n\n\n\n\n\n\n\n\n\n\n\n12rfG3sh9NCWiX3ivPjq2HtdLmbqCrv" +
				"HVEzJubnzFzosMuawymB@europe-north-1.tardigrade.io:7777\n\n12" +
				"tRQrMTWUWwzwGh18i7Fqs67kmdhH9t6aToeiwbo5mfS2rUmo@us2.storj.i" +
				"o:7777                                                      "),
			satellites: make(map[storj.NodeURL]struct{}),
			expectedSatellites: map[storj.NodeURL]struct{}{
				validNodeURLs[3]: {},
				validNodeURLs[5]: {},
				validNodeURLs[6]: {},
			},
		},
	}

	for i, tc := range tests {
		satellites := make(map[storj.NodeURL]struct{})
		err = readSatelliteList(tc.input, satellites)
		require.NoError(t, err, tc.name)
		require.Equal(t, tc.expectedSatellites, satellites, i, tc.name)
	}
}

func TestReadSatelliteList_Invalid(t *testing.T) {
	for i, input := range []string{
		"121RTSDpyNZVcEU84Ticf2L1ntiuUimbWgfATz21tuvgk3vzoA6@ap1.storj.io:777" +
			"7\n# 1wFTAgs9DP5RSnCqKV1eLf6N9wtk4EAtmN5DpSxcs8EjT69tGE@saltlake" +
			".tardigrade.io:7777\nthere should be another satellite...",
		"121RTSDpyNZVcEU84Ticf2L1ntiuUimbWgfATz21tuvgk3vzoA6@ap1.storj.io:777" +
			"71wFTAgs9DP5RSnCqKV1eLf6N9wtk4EAtmN5DpSxcs8EjT69tGE@saltlake.tar" +
			"digrade.io:7777\n",
	} {
		require.Error(t, readSatelliteList([]byte(input), make(map[storj.NodeURL]struct{})), i)
	}
}

func TestGetHTTPList(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	const test = "This is a test."

	ts1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, test)
	}))
	defer ts1.Close()

	b, err := getHTTPList(ctx, ts1.URL)
	require.NoError(t, err)
	require.Equal(t, test, string(b))
}

func TestGetHTTPList_Invalid(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
	}))
	defer ts2.Close()

	for i, url := range []string{
		ts2.URL,
		"jane@computer.local",
		"ftp://ab:cd",
	} {
		_, err := getHTTPList(ctx, url)
		require.Error(t, err, i)
	}
}

func TestParseSatelliteURL(t *testing.T) {
	for i, tc := range []struct {
		s               string
		expectedID      string
		expectedAddress string
	}{
		{
			s:               "118UWpMCHzs6CvSgWd9BfFVjw5K9pZbJjkfZJexMtSkmKxvvAW@satellite.stefan-benten.de:7777",
			expectedID:      "118UWpMCHzs6CvSgWd9BfFVjw5K9pZbJjkfZJexMtSkmKxvvAW",
			expectedAddress: "satellite.stefan-benten.de:7777",
		},
		{
			s:               "118UWpMCHzs6CvSgWd9BfFVjw5K9pZbJjkfZJexMtSkmKxvvAW@",
			expectedID:      "118UWpMCHzs6CvSgWd9BfFVjw5K9pZbJjkfZJexMtSkmKxvvAW",
			expectedAddress: "",
		},
		{
			s:               "saltlake.tardigrade.io:7777",
			expectedID:      "1wFTAgs9DP5RSnCqKV1eLf6N9wtk4EAtmN5DpSxcs8EjT69tGE",
			expectedAddress: "saltlake.tardigrade.io:7777",
		},
	} {
		expectedID, err := storj.NodeIDFromString(tc.expectedID)
		require.NoError(t, err, i)
		url, err := ParseSatelliteURL(tc.s)
		require.NoError(t, err, i)
		require.Equal(t, expectedID, url.ID, i)
		require.Equal(t, tc.expectedAddress, url.Address, i)
	}
}

func TestParseSatelliteURL_Invalid(t *testing.T) {
	for i, s := range []string{
		"10.0.0.1:7777",
		"\x8c\x8d\x6a\x4f\x05\x02\x23\xa4\x07\x56",
	} {
		_, err := ParseSatelliteURL(s)
		require.Error(t, err, i)
	}
}
