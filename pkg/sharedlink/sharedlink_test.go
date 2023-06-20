// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package sharedlink_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"storj.io/gateway-mt/pkg/sharedlink"
)

func TestParse(t *testing.T) {
	_, err := sharedlink.Parse("something")
	require.Error(t, err)

	_, err = sharedlink.Parse("https://something.com/test")
	require.Error(t, err)

	link, err := sharedlink.Parse("https://link.storjshare.io/s/abc123/mybucket/myfiles/test.jpg?raw=1")
	require.NoError(t, err)
	require.Equal(t, "abc123", link.AccessKey)

	link, err = sharedlink.Parse("https://link.storjshare.io/raw/abc123/mybucket/myfiles/test.jpg")
	require.NoError(t, err)
	require.Equal(t, "abc123", link.AccessKey)

	link, err = sharedlink.Parse("https://gateway.storjshare.io/mybucket/myfiles/test.jpg?AWSAccessKeyId=abc123")
	require.NoError(t, err)
	require.Equal(t, "abc123", link.AccessKey)

	link, err = sharedlink.Parse("https://gateway.storjshare.io/mybucket/myfiles/test.jpg?X-Amz-Credential=abc123/20130524/us-east-1/s3/aws4_request")
	require.NoError(t, err)
	require.Equal(t, "abc123", link.AccessKey)
}
