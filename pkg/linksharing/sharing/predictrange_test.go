// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"storj.io/uplink"
)

// commented out tests fail because predictRange doesn't know the length or
// because it doesn't support multiple ranges.
var PredictRangeTests = []struct {
	s      string
	length int64
	o      *uplink.DownloadOptions
	e      error
}{
	{"", 0, nil, nil},
	{"", 1000, nil, nil},
	{"foo", 0, nil, errors.New("invalid range")},
	{"bytes=", 0, nil, errors.New("range prediction failed")},
	{"bytes=7", 10, nil, errors.New("invalid range")},
	{"bytes= 7 ", 10, nil, errors.New("invalid range")},
	// {"bytes=1-", 0, nil, errors.New("invalid range")},
	{"bytes=5-4", 10, nil, errors.New("invalid range")},
	// {"bytes=0-2,5-4", 10, nil, errors.New("invalid range")},
	// {"bytes=2-5,4-3", 10, nil, errors.New("invalid range")},
	{"bytes=--5,4--3", 10, nil, errors.New("invalid range")},
	{"bytes=--6", 10, nil, errors.New("invalid range")},
	{"bytes=--0", 10, nil, errors.New("invalid range")},
	{"bytes=---0", 10, nil, errors.New("invalid range")},
	{"bytes=-6-", 10, nil, errors.New("invalid range")},
	{"bytes=A-", 10, nil, errors.New("invalid range")},
	{"bytes=A- ", 10, nil, errors.New("invalid range")},
	{"bytes=A-Z", 10, nil, errors.New("invalid range")},
	{"bytes= -Z", 10, nil, errors.New("invalid range")},
	{"bytes=5-Z", 10, nil, errors.New("invalid range")},
	{"bytes=Ran-dom, garbage", 10, nil, errors.New("invalid range")},
	{"bytes=0x01-0x02", 10, nil, errors.New("invalid range")},
	{"bytes=         ", 10, nil, errors.New("range prediction failed")},
	{"bytes= , , ,   ", 10, nil, errors.New("range prediction failed")},

	{"bytes=0-9", 10, &uplink.DownloadOptions{Offset: 0, Length: 10}, nil},
	{"bytes=0-", 10, &uplink.DownloadOptions{Offset: 0, Length: -1}, nil},
	{"bytes=5-", 10, &uplink.DownloadOptions{Offset: 5, Length: -1}, nil},
	// {"bytes=0-20", 10, &uplink.DownloadOptions{Offset: 0,Length: 10}, nil},
	// {"bytes=15-,0-5", 10, &uplink.DownloadOptions{Offset: 0,Length: 6}, nil},
	{"bytes=1-2,5-", 10, &uplink.DownloadOptions{Offset: 1, Length: 2}, nil},
	{"bytes=-2 , 7-", 11, &uplink.DownloadOptions{Offset: -2, Length: -1}, nil},
	{"bytes=0-0 ,2-2, 7-", 11, &uplink.DownloadOptions{Offset: 0, Length: 1}, nil},
	{"bytes=-5", 10, &uplink.DownloadOptions{Offset: -5, Length: -1}, nil},
	// {"bytes=-15", 10, &uplink.DownloadOptions{Offset: 0,Length: 10}, nil},
	{"bytes=0-499", 10000, &uplink.DownloadOptions{Offset: 0, Length: 500}, nil},
	{"bytes=500-999", 10000, &uplink.DownloadOptions{Offset: 500, Length: 500}, nil},
	{"bytes=-500", 10000, &uplink.DownloadOptions{Offset: -500, Length: -1}, nil},
	{"bytes=9500-", 10000, &uplink.DownloadOptions{Offset: 9500, Length: -1}, nil},
	{"bytes=0-0,-1", 10000, &uplink.DownloadOptions{Offset: 0, Length: 1}, nil},
	{"bytes=500-600,601-999", 10000, &uplink.DownloadOptions{Offset: 500, Length: 101}, nil},
	{"bytes=500-700,601-999", 10000, &uplink.DownloadOptions{Offset: 500, Length: 201}, nil},

	// Match Apache laxity:
	{"bytes=   1 -2   ,  4- 5, 7 - 8 , ,,", 11, &uplink.DownloadOptions{Offset: 1, Length: 2}, nil},
}

func TestPredictRange(t *testing.T) {
	for _, test := range PredictRangeTests {
		options, err := predictRange(test.s)
		if test.e != nil {
			require.EqualError(t, err, test.e.Error(), test)
		} else {
			require.NoError(t, err)
		}
		require.Equal(t, test.o, options)
	}
}
