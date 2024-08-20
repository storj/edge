// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package middleware

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"gopkg.in/webhelp.v1/whmon"
	"gopkg.in/webhelp.v1/whroute"

	"storj.io/common/uuid"
	"storj.io/edge/pkg/accesslogs"
	"storj.io/edge/pkg/server/gwlog"
	"storj.io/edge/pkg/trustedip"
	"storj.io/uplink"
)

var (
	errInvalidConfigFormat    = errs.Class("invalid access log configuration format")
	errParsingAccessGrant     = errs.Class("failed to parse access grant")
	errParsingProjectID       = errs.Class("failed to parse project ID")
	errWatchedBucketEmpty     = errs.Class("watched bucket is empty")
	errDestinationBucketEmpty = errs.Class("destination bucket is empty")
)

// WatchedBucket represents a bucket to collect logs from.
type WatchedBucket struct {
	ProjectID  uuid.UUID
	BucketName string
}

// DestinationLogBucket represents a destination bucket to store logs.
type DestinationLogBucket struct {
	BucketName string
	Storage    accesslogs.Storage
	Prefix     string
}

// AccessLogConfig is a map of WatchedBucket to DestinationLogBucket configuration.
type AccessLogConfig map[WatchedBucket]DestinationLogBucket

// AccessLog is a middleware function that logs access information for incoming HTTP requests.
func AccessLog(log *zap.Logger, p *accesslogs.Processor, config AccessLogConfig) mux.MiddlewareFunc {
	return func(h http.Handler) http.Handler {
		return whmon.MonitorResponse(whroute.HandlerFunc(h, func(w http.ResponseWriter, r *http.Request) {
			rw := w.(whmon.ResponseWriter)
			startTime := time.Now()
			gl, ok := gwlog.FromContext(r.Context())
			if !ok {
				gl = gwlog.New()
				r = r.WithContext(gl.WithContext(r.Context()))
			}

			h.ServeHTTP(w, r)

			var publicProjectID string
			credentials := GetAccess(r.Context())
			if credentials != nil {
				publicProjectID = credentials.PublicProjectID
			}

			if publicProjectID == "" {
				return
			}

			logEntry := extractLogEntry(r, rw, startTime, gl)
			processLogEntry(log, p, config, publicProjectID, gl.BucketName, &logEntry)
		}))
	}
}

// ParseAccessLogConfig parses a slice of strings representing access log configurations.
func ParseAccessLogConfig(log *zap.Logger, config []string) (AccessLogConfig, error) {
	c := make(AccessLogConfig)
	for _, line := range config {
		parts := strings.Split(line, ":")
		if len(parts) != 5 {
			return AccessLogConfig{}, errInvalidConfigFormat.New("expected 5 parts, got %d", len(parts))
		}

		parsedAccessGrant, err := uplink.ParseAccess(parts[3])
		if err != nil {
			return AccessLogConfig{}, errParsingAccessGrant.New("%s", err)
		}

		parsedProjectID, err := uuid.FromString(parts[0])
		if err != nil {
			return AccessLogConfig{}, errParsingProjectID.New("%s", err)
		}

		if parts[1] == "" {
			return AccessLogConfig{}, errWatchedBucketEmpty.New("")
		}

		if parts[2] == "" {
			return AccessLogConfig{}, errDestinationBucketEmpty.New("")
		}

		c[WatchedBucket{
			ProjectID:  parsedProjectID,
			BucketName: parts[1],
		}] = DestinationLogBucket{
			BucketName: parts[2],
			Storage:    accesslogs.NewStorjStorage(parsedAccessGrant),
			Prefix:     parts[4],
		}
	}

	return c, nil
}

// SerializeAccessLogConfig serializes AccessLogConfig into a slice of strings.
func SerializeAccessLogConfig(config AccessLogConfig) ([]string, error) {
	var ret []string

	for watchedBucket, destBucket := range config {
		var serialized string
		if destBucket.Storage != nil {
			if storjStorage, ok := destBucket.Storage.(*accesslogs.StorjStorage); ok {
				var err error
				serialized, err = storjStorage.SerializedAccessGrant()
				if err != nil {
					return nil, err
				}
			}
		}
		ret = append(ret, strings.Join([]string{
			watchedBucket.ProjectID.String(),
			watchedBucket.BucketName,
			destBucket.BucketName,
			serialized,
			destBucket.Prefix,
		}, ":"))
	}

	return ret, nil
}

func populateLogEntry(r *http.Request, rw whmon.ResponseWriter, startTime time.Time, gl *gwlog.Log) accesslogs.S3AccessLogEntryOptions {
	// todo: set the right object size based on request type.
	// S3 sets it as the part size if a part upload request, otherwise total object size for get, put, head object requests.
	entryOptions := accesslogs.S3AccessLogEntryOptions{
		BucketOwner:        "-",
		Bucket:             gl.BucketName,
		Time:               startTime,
		RemoteIP:           trustedip.GetClientIP(trustedip.NewListTrustAll(), r),
		Requester:          "-",
		RequestID:          gl.RequestID,
		Operation:          gl.API,
		Key:                gl.ObjectName,
		RequestURI:         fmt.Sprintf("%s %s %s", r.Method, r.RequestURI, "HTTP/1.1"),
		HTTPStatus:         rw.StatusCode(),
		ErrorCode:          gl.TagValue("error"),
		BytesSent:          rw.Written(),
		ObjectSize:         nil,
		TotalTime:          time.Since(startTime) / time.Millisecond,
		TurnAroundTime:     0,
		Referer:            "-",
		UserAgent:          r.UserAgent(),
		VersionID:          "-",
		HostID:             "-",
		SignatureVersion:   "SigV4",
		CipherSuite:        "-",
		AuthenticationType: "-",
		TLSVersion:         "-",
		AccessPointARN:     "-",
		ACLRequired:        "-",
	}

	if r.Header.Get("Referer") != "" {
		entryOptions.Referer = r.Header.Get("Referer")
	}
	if rw.Header().Get("x-amz-version-id") != "" {
		entryOptions.VersionID = rw.Header().Get("x-amz-version-id")
	}
	if r.TLS != nil {
		entryOptions.CipherSuite = tls.CipherSuiteName(r.TLS.CipherSuite)
		entryOptions.TLSVersion = tls.VersionName(r.TLS.Version)
	}
	hostname, err := os.Hostname()
	if err == nil {
		hostIdSha256 := sha256.Sum256([]byte(hostname))
		entryOptions.HostID = hex.EncodeToString(hostIdSha256[:])
	}
	if _, ok := r.Header["Authentication"]; ok {
		entryOptions.AuthenticationType = "AuthHeader"
	} else {
		values, _ := url.ParseQuery(r.RequestURI)
		if _, ok := values["X-Amz-Credential"]; ok {
			entryOptions.AuthenticationType = "QueryString"
		}
	}
	credentials := GetAccess(r.Context())
	if credentials != nil {
		entryOptions.BucketOwner = credentials.PublicProjectID
		entryOptions.Requester = credentials.PublicProjectID
	}

	return entryOptions
}

func extractLogEntry(r *http.Request, rw whmon.ResponseWriter, startTime time.Time, gl *gwlog.Log) accesslogs.S3AccessLogEntry {
	return *accesslogs.NewS3AccessLogEntry(populateLogEntry(r, rw, startTime, gl))
}

func processLogEntry(log *zap.Logger, p *accesslogs.Processor, config AccessLogConfig, publicProjectID, bucketName string, logEntry *accesslogs.S3AccessLogEntry) {
	parsedPublicProjectID, err := uuid.FromString(publicProjectID)
	if err != nil {
		log.Error("Error parsing public project ID from authservice",
			zap.Error(err),
			zap.String("publicProjectID", publicProjectID))
		return
	}

	if c, ok := config[WatchedBucket{
		ProjectID:  parsedPublicProjectID,
		BucketName: bucketName,
	}]; ok {
		err = p.QueueEntry(c.Storage, accesslogs.Key{
			PublicProjectID: parsedPublicProjectID,
			Bucket:          c.BucketName,
			Prefix:          c.Prefix,
		}, logEntry)
		if err != nil {
			log.Error("Error queuing access log entry", zap.Error(err))
		}
	}
}
