// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package certstorage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/caddyserver/certmagic"
	"github.com/spacemonkeygo/monkit/v3"
	"go.uber.org/zap"

	"storj.io/edge/pkg/s3lock"
)

// S3Options configures an S3 certstorage backend.
type S3Options struct {
	// Bucket is the bucket to use, with an optional prefix ("bucket/prefix").
	Bucket string
	// Region is the AWS region. It falls back to the environment/shared config
	// when empty.
	Region string
	// AccessKeyID and SecretAccessKey are optional static credentials. When
	// empty, the AWS default credential chain is used.
	AccessKeyID     string
	SecretAccessKey string
	// Endpoint optionally overrides the S3 endpoint (for S3-compatible
	// services). When set, path-style addressing is used.
	Endpoint string
}

// S3 implements certmagic's Storage interface on top of AWS S3.
type S3 struct {
	logger *zap.Logger
	client *s3.Client

	bucket string
	prefix string

	locks map[string]*s3lock.Mutex
	mu    sync.Mutex
}

// NewS3 returns an initialized S3.
func NewS3(ctx context.Context, logger *zap.Logger, opts S3Options) (_ *S3, err error) {
	client, err := newS3Client(ctx, opts)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	bucket, prefix, _ := strings.Cut(opts.Bucket, "/")
	if prefix != "" {
		prefix = strings.TrimSuffix(prefix, "/") + "/"
	}

	s := &S3{
		logger: logger,
		client: client,
		bucket: bucket,
		prefix: prefix,
		locks:  make(map[string]*s3lock.Mutex),
	}

	// Verify we can reach the bucket and have list permission.
	if _, err := s.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:  aws.String(s.bucket),
		Prefix:  aws.String(s.prefix),
		MaxKeys: aws.Int32(1),
	}); err != nil {
		return nil, Error.Wrap(err)
	}

	return s, nil
}

func newS3Client(ctx context.Context, opts S3Options) (*s3.Client, error) {
	loadOpts := []func(*awsconfig.LoadOptions) error{}
	if opts.Region != "" {
		loadOpts = append(loadOpts, awsconfig.WithRegion(opts.Region))
	}
	if opts.AccessKeyID != "" {
		loadOpts = append(loadOpts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(opts.AccessKeyID, opts.SecretAccessKey, ""),
		))
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		if opts.Endpoint != "" {
			o.BaseEndpoint = aws.String(opts.Endpoint)
			o.UsePathStyle = true
		}
	}), nil
}

var _ certmagic.Storage = (*S3)(nil) // make sure S3 implements certmagic.Storage

// key prepends the configured prefix to a certmagic key.
func (s *S3) key(name string) string { return s.prefix + name }

// Lock implements certmagic's Storage interface.
func (s *S3) Lock(ctx context.Context, name string) (err error) {
	defer mon.Task()(&ctx)(&err)

	s.mu.Lock()
	lock, ok := s.locks[name]
	if !ok {
		m, err := s3lock.NewMutex(ctx, s3lock.Options{
			Client: s.client,
			Name:   s.key(name),
			Bucket: s.bucket,
			Logger: s.logger.Named("distributed lock/" + name).Sugar(),
		})
		if err != nil {
			s.mu.Unlock()
			return Error.Wrap(err)
		}
		s.locks[name], lock = m, m
	}
	s.mu.Unlock()
	mon.Event("certstorage_lockcache", monkit.NewSeriesTag("hit", strconv.FormatBool(ok)))
	return Error.Wrap(lock.Lock(ctx))
}

// Unlock implements certmagic's Storage interface.
func (s *S3) Unlock(ctx context.Context, name string) (err error) {
	defer mon.Task()(&ctx)(&err)

	s.mu.Lock()
	lock, ok := s.locks[name]
	if !ok {
		s.mu.Unlock()
		mon.Event("certstorage_mutex_not_exists")
		return Error.New("mutex for %s not exists", name)
	}
	s.mu.Unlock()
	return Error.Wrap(lock.Unlock(ctx))
}

// Store implements certmagic's Storage interface.
func (s *S3) Store(ctx context.Context, key string, value []byte) (err error) {
	defer mon.Task()(&ctx)(&err)

	s.logger.Debug("store", zap.String("bucket", s.bucket), zap.String("key", key))

	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.key(key)),
		Body:   bytes.NewReader(value),
	})
	return Error.Wrap(err)
}

// Load implements certmagic's Storage interface.
func (s *S3) Load(ctx context.Context, key string) (_ []byte, err error) {
	defer mon.Task()(&ctx)(&err)

	s.logger.Debug("load", zap.String("bucket", s.bucket), zap.String("key", key))

	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.key(key)),
	})
	if err != nil {
		if isNotFound(err) {
			return nil, Error.Wrap(fs.ErrNotExist)
		}
		return nil, Error.Wrap(err)
	}
	defer func() { err = Error.Wrap(errors.Join(err, out.Body.Close())) }()

	return io.ReadAll(out.Body)
}

// Delete implements certmagic's Storage interface.
func (s *S3) Delete(ctx context.Context, key string) (err error) {
	defer mon.Task()(&ctx)(&err)

	s.logger.Debug("delete", zap.String("bucket", s.bucket), zap.String("key", key))

	// S3 DeleteObject is idempotent (no error on a missing key), but certmagic
	// expects fs.ErrNotExist, so check existence first.
	if !s.Exists(ctx, key) {
		return Error.Wrap(fs.ErrNotExist)
	}

	_, err = s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.key(key)),
	})
	return Error.Wrap(err)
}

// Exists implements certmagic's Storage interface.
func (s *S3) Exists(ctx context.Context, key string) bool {
	var err error

	defer mon.Task()(&ctx)(&err)

	_, err = s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.key(key)),
	})
	return err == nil
}

// List implements certmagic's Storage interface.
func (s *S3) List(ctx context.Context, prefix string, recursive bool) (_ []string, err error) {
	defer mon.Task()(&ctx)(&err)

	s.logger.Debug("list", zap.String("bucket", s.bucket), zap.String("prefix", prefix), zap.Bool("recursive", recursive))

	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(s.key(prefix)),
		// Request URL-encoded key names so that keys containing characters that
		// aren't valid in XML (e.g. control characters) don't break decoding of
		// the XML response body.
		EncodingType: types.EncodingTypeUrl,
	}
	if !recursive {
		input.Delimiter = aws.String("/")
	}

	var result []string
	paginator := s3.NewListObjectsV2Paginator(s.client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, Error.Wrap(err)
		}
		for _, p := range page.CommonPrefixes {
			key, err := decodeKey(aws.ToString(p.Prefix))
			if err != nil {
				return nil, err
			}
			result = append(result, strings.TrimPrefix(key, s.prefix))
		}
		for _, o := range page.Contents {
			key, err := decodeKey(aws.ToString(o.Key))
			if err != nil {
				return nil, err
			}
			result = append(result, strings.TrimPrefix(key, s.prefix))
		}
	}
	sort.Strings(result)

	return result, nil
}

// decodeKey reverses the URL encoding S3 applies to key names when EncodingType
// is "url". S3 uses application/x-www-form-urlencoded encoding (a space becomes
// "+" and a literal "+" becomes "%2B"), so QueryUnescape is the correct inverse.
func decodeKey(key string) (string, error) {
	decoded, err := url.QueryUnescape(key)
	return decoded, Error.Wrap(err)
}

// Stat implements certmagic's Storage interface.
func (s *S3) Stat(ctx context.Context, key string) (_ certmagic.KeyInfo, err error) {
	defer mon.Task()(&ctx)(&err)

	var keyInfo certmagic.KeyInfo

	s.logger.Debug("stat", zap.String("bucket", s.bucket), zap.String("key", key))

	out, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.key(key)),
	})
	if err != nil {
		if isNotFound(err) {
			return keyInfo, Error.Wrap(fs.ErrNotExist)
		}
		return keyInfo, Error.Wrap(err)
	}

	keyInfo.Key = key
	keyInfo.IsTerminal = true // S3 returns 404 when querying a prefix
	keyInfo.Modified = aws.ToTime(out.LastModified)
	keyInfo.Size = aws.ToInt64(out.ContentLength)

	return keyInfo, nil
}

// isNotFound reports whether err is an S3 404 (NoSuchKey / NotFound).
func isNotFound(err error) bool {
	var re interface{ HTTPStatusCode() int }
	if errors.As(err, &re) {
		return re.HTTPStatusCode() == 404
	}
	return false
}
