// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"storj.io/common/testcontext"
)

func TestStaticDNSClient(t *testing.T) {
	ctx := testcontext.New(t)

	client, err := ParseStaticDNSClientFromZoneFile([]byte(strings.Join(
		[]string{
			"downloads.example.com.    	IN	CNAME	link.storjshare.io.",
			"txt-downloads.example.com.	IN	TXT  	storj-root:files",
			"txt-downloads.example.com.	IN	TXT  	storj-access:ju5umq3nrhaf6xo6srpb4xvldglq",
		},
		"\n",
	)))
	require.NoError(t, err)

	t.Run("ValidateCNAME", func(t *testing.T) {
		base, err := parseURLBase("http://link.storjshare.io")
		require.NoError(t, err)

		err = client.ValidateCNAME(ctx, "downloads.example.com", []*url.URL{base})
		require.NoError(t, err)

		err = client.ValidateCNAME(ctx, "downloads.example.local", []*url.URL{base})
		require.Error(t, err)
	})

	t.Run("LookupTXTRecordSet", func(t *testing.T) {
		set, err := client.LookupTXTRecordSet(ctx, "txt-downloads.example.com")
		require.NoError(t, err)

		require.Equal(t, "files", set.Lookup("storj-root"))
		require.Equal(t, "ju5umq3nrhaf6xo6srpb4xvldglq", set.Lookup("storj-access"))
	})
}
