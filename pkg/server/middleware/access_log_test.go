// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeebo/errs"
	"go.uber.org/zap/zaptest"
	"gopkg.in/webhelp.v1/whmon"

	"storj.io/common/testcontext"
	"storj.io/common/uuid"
	"storj.io/edge/pkg/accesslogs"
	"storj.io/edge/pkg/authclient"
	"storj.io/edge/pkg/server/gwlog"
	"storj.io/minio/cmd/logger"
	"storj.io/uplink"
)

func TestSerializeAccessLogConfig(t *testing.T) {
	testAccessGrant, err := uplink.ParseAccess(testAccessGrant)
	require.NoError(t, err)

	testCases := []struct {
		config   AccessLogConfig
		expected []string
	}{
		{
			config: AccessLogConfig{
				WatchedBucket{
					ProjectID:  uuid.UUID{1, 2, 3},
					BucketName: "test",
				}: DestinationLogBucket{
					BucketName: "mybucket",
					Storage:    accesslogs.NewStorjStorage(testAccessGrant),
					Prefix:     "myprefix",
				},
			},
			expected: []string{"01020300-0000-0000-0000-000000000000:test:mybucket:13J4Upun87ATb3T5T5sDXVeQaCzWFZeF9Ly4ELfxS5hUwTL8APEkwahTEJ1wxZjyErimiDs3kgid33kDLuYPYtwaY7Toy32mCTapfrUB814X13RiA844HPWK3QLKZb9cAoVceTowmNZXWbcUMKNbkMHCURE4hn8ZrdHPE3S86yngjvDxwKmarfGx:myprefix"},
		},
		{
			config: AccessLogConfig{
				WatchedBucket{
					ProjectID:  uuid.UUID{1, 2, 3},
					BucketName: "test",
				}: DestinationLogBucket{
					BucketName: "mybucket",
					Storage:    accesslogs.NewStorjStorage(testAccessGrant),
				},
			},
			expected: []string{"01020300-0000-0000-0000-000000000000:test:mybucket:13J4Upun87ATb3T5T5sDXVeQaCzWFZeF9Ly4ELfxS5hUwTL8APEkwahTEJ1wxZjyErimiDs3kgid33kDLuYPYtwaY7Toy32mCTapfrUB814X13RiA844HPWK3QLKZb9cAoVceTowmNZXWbcUMKNbkMHCURE4hn8ZrdHPE3S86yngjvDxwKmarfGx:"},
		},
		{
			config: AccessLogConfig{
				WatchedBucket{
					ProjectID:  uuid.UUID{1, 2, 3},
					BucketName: "test",
				}: DestinationLogBucket{
					BucketName: "mybucket",
					Storage:    accesslogs.NewStorjStorage(testAccessGrant),
					Prefix:     "something/",
				},
				WatchedBucket{
					ProjectID:  uuid.UUID{5, 6, 7},
					BucketName: "foo",
				}: DestinationLogBucket{
					BucketName: "anotherbucket",
					Storage:    accesslogs.NewStorjStorage(testAccessGrant),
				},
			},
			expected: []string{
				"01020300-0000-0000-0000-000000000000:test:mybucket:13J4Upun87ATb3T5T5sDXVeQaCzWFZeF9Ly4ELfxS5hUwTL8APEkwahTEJ1wxZjyErimiDs3kgid33kDLuYPYtwaY7Toy32mCTapfrUB814X13RiA844HPWK3QLKZb9cAoVceTowmNZXWbcUMKNbkMHCURE4hn8ZrdHPE3S86yngjvDxwKmarfGx:something/",
				"05060700-0000-0000-0000-000000000000:foo:anotherbucket:13J4Upun87ATb3T5T5sDXVeQaCzWFZeF9Ly4ELfxS5hUwTL8APEkwahTEJ1wxZjyErimiDs3kgid33kDLuYPYtwaY7Toy32mCTapfrUB814X13RiA844HPWK3QLKZb9cAoVceTowmNZXWbcUMKNbkMHCURE4hn8ZrdHPE3S86yngjvDxwKmarfGx:",
			},
		},
	}
	for i, tc := range testCases {
		serialized, err := SerializeAccessLogConfig(tc.config)
		require.NoError(t, err, i)

		for _, expected := range tc.expected {
			assert.Contains(t, serialized, expected, i)
		}
	}
}

func TestParseAccessLogConfig(t *testing.T) {
	ctx := testcontext.New(t)

	log := zaptest.NewLogger(t)
	defer ctx.Check(log.Sync)

	testAccessGrant, err := uplink.ParseAccess(testAccessGrant)
	require.NoError(t, err)

	testCases := []struct {
		config      []string
		expected    AccessLogConfig
		expectedErr *errs.Class
	}{
		{
			config:      []string{"something"},
			expectedErr: &errInvalidConfigFormat,
		},
		{
			config:      []string{"00000000-0000-0000-0000-000000000000::::"},
			expectedErr: &errParsingAccessGrant,
		},
		{
			config:      []string{"blah:::13J4Upun87ATb3T5T5sDXVeQaCzWFZeF9Ly4ELfxS5hUwTL8APEkwahTEJ1wxZjyErimiDs3kgid33kDLuYPYtwaY7Toy32mCTapfrUB814X13RiA844HPWK3QLKZb9cAoVceTowmNZXWbcUMKNbkMHCURE4hn8ZrdHPE3S86yngjvDxwKmarfGx:"},
			expectedErr: &errParsingProjectID,
		},
		{
			config:      []string{"00000000-0000-0000-0000-000000000000:::13J4Upun87ATb3T5T5sDXVeQaCzWFZeF9Ly4ELfxS5hUwTL8APEkwahTEJ1wxZjyErimiDs3kgid33kDLuYPYtwaY7Toy32mCTapfrUB814X13RiA844HPWK3QLKZb9cAoVceTowmNZXWbcUMKNbkMHCURE4hn8ZrdHPE3S86yngjvDxwKmarfGx:"},
			expectedErr: &errWatchedBucketEmpty,
		},
		{
			config:      []string{"00000000-0000-0000-0000-000000000000:sourcebucket::13J4Upun87ATb3T5T5sDXVeQaCzWFZeF9Ly4ELfxS5hUwTL8APEkwahTEJ1wxZjyErimiDs3kgid33kDLuYPYtwaY7Toy32mCTapfrUB814X13RiA844HPWK3QLKZb9cAoVceTowmNZXWbcUMKNbkMHCURE4hn8ZrdHPE3S86yngjvDxwKmarfGx:"},
			expectedErr: &errDestinationBucketEmpty,
		},
		{
			config: []string{"00000000-0000-0000-0000-000000000000:sourcebucket:mybucket:13J4Upun87ATb3T5T5sDXVeQaCzWFZeF9Ly4ELfxS5hUwTL8APEkwahTEJ1wxZjyErimiDs3kgid33kDLuYPYtwaY7Toy32mCTapfrUB814X13RiA844HPWK3QLKZb9cAoVceTowmNZXWbcUMKNbkMHCURE4hn8ZrdHPE3S86yngjvDxwKmarfGx:"},
			expected: AccessLogConfig{
				WatchedBucket{
					BucketName: "sourcebucket",
				}: DestinationLogBucket{
					BucketName: "mybucket",
					Storage:    accesslogs.NewStorjStorage(testAccessGrant),
				},
			},
		},
		{
			config: []string{"01020300-0000-0000-0000-000000000000:test:mybucket:13J4Upun87ATb3T5T5sDXVeQaCzWFZeF9Ly4ELfxS5hUwTL8APEkwahTEJ1wxZjyErimiDs3kgid33kDLuYPYtwaY7Toy32mCTapfrUB814X13RiA844HPWK3QLKZb9cAoVceTowmNZXWbcUMKNbkMHCURE4hn8ZrdHPE3S86yngjvDxwKmarfGx:myprefix"},
			expected: AccessLogConfig{
				WatchedBucket{
					ProjectID:  uuid.UUID{1, 2, 3},
					BucketName: "test",
				}: DestinationLogBucket{
					BucketName: "mybucket",
					Storage:    accesslogs.NewStorjStorage(testAccessGrant),
					Prefix:     "myprefix",
				},
			},
		},
		{
			config: []string{
				"01020300-0000-0000-0000-000000000000:test:mybucket:13J4Upun87ATb3T5T5sDXVeQaCzWFZeF9Ly4ELfxS5hUwTL8APEkwahTEJ1wxZjyErimiDs3kgid33kDLuYPYtwaY7Toy32mCTapfrUB814X13RiA844HPWK3QLKZb9cAoVceTowmNZXWbcUMKNbkMHCURE4hn8ZrdHPE3S86yngjvDxwKmarfGx:something/",
				"05060700-0000-0000-0000-000000000000:foo:anotherbucket:13J4Upun87ATb3T5T5sDXVeQaCzWFZeF9Ly4ELfxS5hUwTL8APEkwahTEJ1wxZjyErimiDs3kgid33kDLuYPYtwaY7Toy32mCTapfrUB814X13RiA844HPWK3QLKZb9cAoVceTowmNZXWbcUMKNbkMHCURE4hn8ZrdHPE3S86yngjvDxwKmarfGx:",
			},
			expected: AccessLogConfig{
				WatchedBucket{
					ProjectID:  uuid.UUID{1, 2, 3},
					BucketName: "test",
				}: DestinationLogBucket{
					BucketName: "mybucket",
					Storage:    accesslogs.NewStorjStorage(testAccessGrant),
					Prefix:     "something/",
				},
				WatchedBucket{
					ProjectID:  uuid.UUID{5, 6, 7},
					BucketName: "foo",
				}: DestinationLogBucket{
					BucketName: "anotherbucket",
					Storage:    accesslogs.NewStorjStorage(testAccessGrant),
				},
			},
		},
	}
	for i, tc := range testCases {
		config, err := ParseAccessLogConfig(log, tc.config)
		if tc.expectedErr != nil {
			require.True(t, tc.expectedErr.Has(err), i)
			continue
		}

		require.NoError(t, err, i)
		require.Equal(t, tc.expected, config, i)
	}
}

type inMemoryStorage struct {
	buckets map[string]map[string][]byte
}

func newInMemoryStorage() *inMemoryStorage {
	return &inMemoryStorage{
		buckets: make(map[string]map[string][]byte),
	}
}

func (s *inMemoryStorage) Put(_ context.Context, bucket, key string, body []byte) error {
	if _, ok := s.buckets[bucket]; !ok {
		s.buckets[bucket] = make(map[string][]byte)
	}

	s.buckets[bucket][key] = body

	return nil
}

func TestProcessLogEntry(t *testing.T) {
	ctx := testcontext.New(t)

	log := zaptest.NewLogger(t)
	defer ctx.Check(log.Sync)

	p := accesslogs.NewProcessor(log, accesslogs.Options{})
	ctx.Go(p.Run)

	project1, _ := uuid.New()
	project2, _ := uuid.New()
	project3, _ := uuid.New()

	project1Storage := newInMemoryStorage()
	project2Storage := newInMemoryStorage()
	project3Storage := newInMemoryStorage()

	config := AccessLogConfig{
		WatchedBucket{
			ProjectID:  project1,
			BucketName: "bucket1",
		}: DestinationLogBucket{
			BucketName: "destination_bucket1",
			Storage:    project1Storage,
		},
		WatchedBucket{
			ProjectID:  project2,
			BucketName: "bucket2",
		}: DestinationLogBucket{
			BucketName: "destination_bucket2",
			Storage:    project2Storage,
			Prefix:     "destination_prefix2/",
		},
		WatchedBucket{
			ProjectID:  project3,
			BucketName: "bucket3",
		}: DestinationLogBucket{
			BucketName: "destination_bucket3",
			Storage:    project3Storage,
			Prefix:     "destination_prefix3/b/",
		},
	}

	randomTime, _ := time.Parse("2006-01-02T15:04:05", "2024-12-21T13:45:10")
	entry := accesslogs.NewS3AccessLogEntry(accesslogs.S3AccessLogEntryOptions{
		BucketOwner:        "bucketOwner",
		Bucket:             "bucketName",
		Time:               randomTime,
		RemoteIP:           "8.8.8.8",
		Requester:          "publicProjectId",
		RequestID:          "requestId",
		Operation:          "REST.GET.VERSIONING",
		Key:                "/test/puppy.jpg",
		RequestURI:         "GET /DOC-EXAMPLE-BUCKET1/photos/2019/08/puppy.jpg?x-foo=bar HTTP/1.1",
		HTTPStatus:         200,
		ErrorCode:          "NoSuchBucket",
		BytesSent:          1234,
		ObjectSize:         nil,
		TotalTime:          123 * time.Millisecond,
		TurnAroundTime:     0,
		Referer:            "https://example.com",
		UserAgent:          "curl 8.8",
		VersionID:          "versionId",
		HostID:             "hostId",
		SignatureVersion:   "SigV4",
		CipherSuite:        "TLS_AES_128_GCM_SHA256",
		AuthenticationType: "AuthHeader",
		HostHeader:         "gateway.storjshare.io",
		TLSVersion:         "TLSv1.2",
		AccessPointARN:     "-",
		ACLRequired:        "-",
	})

	processLogEntry(log, p, config, project1.String(), "bucket1", entry)
	processLogEntry(log, p, config, project2.String(), "bucket2", entry)
	processLogEntry(log, p, config, project3.String(), "bucket3", entry)

	ctx.Check(p.Close)

	assert.Len(t, project1Storage.buckets["destination_bucket1"], 1)
	assert.Len(t, project2Storage.buckets["destination_bucket2"], 1)
	assert.Len(t, project3Storage.buckets["destination_bucket3"], 1)
}

func TestPopulateLogEntry(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	ts := httptest.NewServer(whmon.MonitorResponse(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := w.(whmon.ResponseWriter)

		rw.WriteHeader(http.StatusForbidden)
		rw.Header().Set("x-amz-version-id", "456")
		_, err := rw.Write([]byte("hello!"))
		require.NoError(t, err)

		credentials := Credentials{
			AuthServiceResponse: authclient.AuthServiceResponse{
				PublicProjectID: "05060700-0000-0000-0000-000000000000",
			},
		}

		time, err := time.Parse(time.RFC3339, "2024-12-21T13:45:10Z")
		require.NoError(t, err)

		entry := populateLogEntry(r.WithContext(context.WithValue(ctx, credentialsCV{}, &credentials)), rw, time, &gwlog.Log{
			ReqInfo: &logger.ReqInfo{
				BucketName: "test-bucket",
				ObjectName: "test-object",
				RequestID:  "123",
				API:        "GetObject",
			},
		})

		assert.Equal(t, "05060700-0000-0000-0000-000000000000", entry.BucketOwner)
		assert.Equal(t, "test-bucket", entry.Bucket)
		assert.Equal(t, "test-object", entry.Key)
		assert.Equal(t, time, entry.Time)
		assert.Equal(t, "GET / HTTP/1.1", entry.RequestURI)
		assert.Equal(t, "123", entry.RequestID)
		assert.Equal(t, "GetObject", entry.Operation)
		assert.Equal(t, "myapp", entry.UserAgent)
		assert.Equal(t, "456", entry.VersionID)
		assert.Equal(t, http.StatusForbidden, entry.HTTPStatus)
		assert.Equal(t, int64(6), entry.BytesSent)
		assert.Equal(t, "/foo", entry.Referer)
		assert.Equal(t, "AuthHeader", entry.AuthenticationType)
	})))
	defer ts.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Referer", "/foo")
	req.Header.Set("Authentication", "bar")
	req.Header.Set("User-Agent", "myapp")

	resp, err := http.DefaultClient.Do(req) //nolint:bodyclose
	require.NoError(t, err)
	ctx.Check(resp.Body.Close)
}
