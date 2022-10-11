// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauth_test

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"storj.io/common/testcontext"
	"storj.io/gateway-mt/pkg/auth/authdb"
	"storj.io/gateway-mt/pkg/auth/badgerauth"
	"storj.io/gateway-mt/pkg/auth/badgerauth/badgerauthtest"
)

func TestBackupRestore(t *testing.T) {
	bucket := "bucket"
	prefix := "prefix"
	endpoint := "localhost:12345"
	s3Client := S3ClientMock{t, bucket, prefix, nil}
	var expectedRecords map[authdb.KeyHash]*authdb.Record
	var expectedEntries []badgerauthtest.ReplicationLogEntryWithTTL

	// Backup db
	badgerauthtest.RunSingleNode(
		t,
		badgerauth.Config{
			ID: badgerauth.NodeID{'t', 'e', 's', 't'},
			Backup: badgerauth.BackupConfig{
				Enabled:  true,
				Endpoint: endpoint,
				Bucket:   bucket,
				Prefix:   prefix,
				Interval: 1 * time.Hour,
			},
		},
		func(ctx *testcontext.Context, t *testing.T, _ *zap.Logger, node *badgerauth.Node) {
			node.Backup.Client = &s3Client
			expectedRecords, _, expectedEntries = badgerauthtest.CreateFullRecords(ctx, t, node, 10)
			node.Backup.SyncCycle.TriggerWait()
		},
	)

	ctx := testcontext.New(t)
	defer ctx.Cleanup()
	log := zaptest.NewLogger(t)
	defer ctx.Check(log.Sync)
	cfg := badgerauth.Config{
		ID:                 badgerauth.NodeID{'a'},
		FirstStart:         true,
		Path:               ctx.File("badger.db"),
		InsecureDisableTLS: true,
	}

	// Restore to new db and ensure it matches
	n, err := badgerauth.New(log, cfg)
	require.NoError(t, err)
	err = n.UnderlyingDB().UnderlyingDB().Load(bytes.NewReader(s3Client.backup), 1)
	require.NoError(t, err)

	cluster := badgerauthtest.Cluster{Nodes: []*badgerauth.Node{n}}
	ensureClusterConvergence(ctx, t, &cluster, expectedRecords, expectedEntries)
}

type S3ClientMock struct {
	t      *testing.T
	bucket string
	prefix string
	backup []byte
}

func (c *S3ClientMock) PutObject(ctx context.Context, bucketName, objectName string, reader io.Reader, objectSize int64,
	opts minio.PutObjectOptions) (info minio.UploadInfo, err error) {
	require.Equal(c.t, c.bucket, bucketName)
	require.Contains(c.t, objectName, c.prefix)
	c.backup, err = io.ReadAll(reader)
	require.NoError(c.t, err)
	return minio.UploadInfo{Bucket: bucketName, Key: objectName, Size: int64(len(c.backup))}, nil
}
