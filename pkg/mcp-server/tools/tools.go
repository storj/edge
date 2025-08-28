// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package tools

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"

	"storj.io/common/rpc/rpcpool"
	"storj.io/common/sync2"
	"storj.io/common/version"
	"storj.io/edge/internal/register"
	"storj.io/edge/pkg/mcp-server/middleware"
	"storj.io/uplink"
	"storj.io/uplink/edge"
	"storj.io/uplink/private/transport"
)

var (
	mon = monkit.Package()

	userAgent = "mcp-server/" + version.Build.Version.String()

	// maximum data size for a single upload or download operation.
	maxDataSize       = 10 * 1024 * 1024                           // 10 MiB
	maxDataSizeBase64 = int(math.Ceil(float64(maxDataSize)/3) * 4) // maxDataSize when base64 encoded

	maxBucketsLimit = 1000
	maxObjectsLimit = 1000
	maxUploadsLimit = 1000

	errUnauthorized = errs.New("unauthorized access")
)

// Tools is a collection of MCP server tools.
type Tools struct {
	config Config

	satelliteConnectionPool *rpcpool.Pool
	connectionPool          *rpcpool.Pool
}

// Config is a config struct for configuring Tools.
type Config struct {
	LinkSharingURL          string
	AuthServiceURL          string
	SatelliteConnectionPool rpcpool.Options
	ConnectionPool          rpcpool.Options
}

// New creates a new Tools.
func New(config Config) *Tools {
	return &Tools{
		config:                  config,
		satelliteConnectionPool: rpcpool.New(config.SatelliteConnectionPool),
		connectionPool:          rpcpool.New(config.ConnectionPool),
	}
}

const (
	// ToolListBuckets is the name of a tool for listing buckets.
	ToolListBuckets = "list_buckets"

	// ToolCreateBucket is the name of a tool for creating a bucket.
	ToolCreateBucket = "create_bucket"

	// ToolDeleteBucket is the name of a tool for deleting a bucket.
	ToolDeleteBucket = "delete_bucket"

	// ToolDeleteBucketWithObjects is the name of a tool for deleting a bucket and all its objects.
	ToolDeleteBucketWithObjects = "delete_bucket_with_objects"

	// ToolEnsureBucket is the name of a tool for ensuring a bucket exists.
	ToolEnsureBucket = "ensure_bucket"

	// ToolStatBucket is the name of a tool for getting statistics about a bucket.
	ToolStatBucket = "stat_bucket"

	// ToolListObjects is the name of a tool for listing objects in a bucket.
	ToolListObjects = "list_objects"

	// ToolMoveObject is the name of a tool for moving an object.
	ToolMoveObject = "move_object"

	// ToolCopyObject is the name of a tool for copying an object.
	ToolCopyObject = "copy_object"

	// ToolStatObject is the name of a tool for getting statistics about an object.
	ToolStatObject = "stat_object"

	// ToolUpdateObjectMetadata is the name of a tool for updating object metadata.
	ToolUpdateObjectMetadata = "update_object_metadata"

	// ToolDeleteObject is the name of a tool for deleting an object.
	ToolDeleteObject = "delete_object"

	// ToolDownloadObject is the name of a tool for downloading an object.
	ToolDownloadObject = "download_object"

	// ToolUploadObject is the name of a tool for uploading an object.
	ToolUploadObject = "upload_object"

	// ToolListUploads is the name of a tool for listing multipart uploads.
	ToolListUploads = "list_uploads"

	// ToolListUploadParts is the name of a tool for listing parts of a multipart upload.
	ToolListUploadParts = "list_upload_parts"

	// ToolBeginUpload is the name of a tool for beginning a multipart upload.
	ToolBeginUpload = "begin_upload"

	// ToolUploadPart is the name of a tool for uploading a part in a multipart upload.
	ToolUploadPart = "upload_part"

	// ToolCommitUpload is the name of a tool for committing a multipart upload.
	ToolCommitUpload = "commit_upload"

	// ToolAbortUpload is the name of a tool for aborting a multipart upload.
	ToolAbortUpload = "abort_upload"

	// ToolShareURL is the name of a tool for generating a public sharing URL.
	ToolShareURL = "share_url"
)

// Add adds the tools to an MCP server.
func (t *Tools) Add(mcpServer *server.MCPServer) {
	// Register all bucket management tools
	mcpServer.AddTool(mcp.NewTool(ToolListBuckets,
		mcp.WithDescription("List available storage buckets with cursor-based pagination. Use limit=10 for quick previews, limit=100 for full listings."),
		mcp.WithString("cursor", mcp.Description("Cursor for pagination (use nextCursor from previous response)"), mcp.DefaultString("")),
		mcp.WithNumber("limit", mcp.Description("Maximum number of buckets to return"), mcp.Min(1), mcp.Max(float64(maxBucketsLimit)), mcp.DefaultNumber(float64(maxBucketsLimit))),
	), t.ListBuckets)

	mcpServer.AddTool(mcp.NewTool(ToolCreateBucket,
		mcp.WithDescription("Create a new storage bucket. Bucket names must be globally unique. Use ensure_bucket if you want to create or verify existence."),
		mcp.WithString("bucket", mcp.Description("Name of the bucket to create"), mcp.Required()),
	), t.CreateBucket)

	mcpServer.AddTool(mcp.NewTool(ToolDeleteBucket,
		mcp.WithDescription("Delete an empty storage bucket. Bucket must be empty. Use delete_bucket_with_objects to delete non-empty buckets."),
		mcp.WithString("bucket", mcp.Description("Name of the bucket to delete"), mcp.Required()),
	), t.DeleteBucket)

	mcpServer.AddTool(mcp.NewTool(ToolDeleteBucketWithObjects,
		mcp.WithDescription("Delete a storage bucket and all its objects. WARNING: This permanently deletes all data in the bucket. Use with caution."),
		mcp.WithString("bucket", mcp.Description("Name of the bucket to delete"), mcp.Required()),
	), t.DeleteBucketWithObjects)

	mcpServer.AddTool(mcp.NewTool(ToolEnsureBucket,
		mcp.WithDescription("Ensure a storage bucket exists (create if it doesn't exist). Idempotent operation - safe to call multiple times. Preferred over create_bucket for most use cases."),
		mcp.WithString("bucket", mcp.Description("Name of the bucket to ensure exists"), mcp.Required()),
	), t.EnsureBucket)

	mcpServer.AddTool(mcp.NewTool(ToolStatBucket,
		mcp.WithDescription("Get statistics and information about a storage bucket"),
		mcp.WithString("bucket", mcp.Description("Name of the bucket to get statistics for"), mcp.Required()),
	), t.StatBucket)

	// Register all object management tools
	mcpServer.AddTool(mcp.NewTool(ToolListObjects,
		mcp.WithDescription("List objects in a storage bucket with optional prefix filtering and cursor-based pagination. Use prefix to filter by folder-like paths (e.g., 'photos/' for all photos). Common workflow: list_objects -> stat_object -> download_object"),
		mcp.WithString("bucket", mcp.Description("Name of the bucket to list objects from"), mcp.Required()),
		mcp.WithString("prefix", mcp.Description("Prefix to filter objects"), mcp.DefaultString("")),
		mcp.WithString("cursor", mcp.Description("Cursor for pagination (use nextCursor from previous response)"), mcp.DefaultString("")),
		mcp.WithNumber("limit", mcp.Description("Maximum number of objects to return"), mcp.Min(1), mcp.Max(float64(maxObjectsLimit)), mcp.DefaultNumber(float64(maxObjectsLimit))),
	), t.ListObjects)

	mcpServer.AddTool(mcp.NewTool(ToolMoveObject,
		mcp.WithDescription("Move an object from one location to another"),
		mcp.WithString("srcBucket", mcp.Description("Source bucket name"), mcp.Required()),
		mcp.WithString("srcKey", mcp.Description("Source object key"), mcp.Required()),
		mcp.WithString("destBucket", mcp.Description("Destination bucket name"), mcp.Required()),
		mcp.WithString("destKey", mcp.Description("Destination object key"), mcp.Required()),
	), t.MoveObject)

	mcpServer.AddTool(mcp.NewTool(ToolCopyObject,
		mcp.WithDescription("Copy an object from one location to another"),
		mcp.WithString("srcBucket", mcp.Description("Source bucket name"), mcp.Required()),
		mcp.WithString("srcKey", mcp.Description("Source object key"), mcp.Required()),
		mcp.WithString("destBucket", mcp.Description("Destination bucket name"), mcp.Required()),
		mcp.WithString("destKey", mcp.Description("Destination object key"), mcp.Required()),
	), t.CopyObject)

	mcpServer.AddTool(mcp.NewTool(ToolStatObject,
		mcp.WithDescription("Get statistics and metadata for a specific object"),
		mcp.WithString("bucket", mcp.Description("Name of the bucket containing the object"), mcp.Required()),
		mcp.WithString("key", mcp.Description("Object key"), mcp.Required()),
	), t.StatObject)

	mcpServer.AddTool(mcp.NewTool(ToolUpdateObjectMetadata,
		mcp.WithDescription("Update metadata for a specific object"),
		mcp.WithString("bucket", mcp.Description("Name of the bucket containing the object"), mcp.Required()),
		mcp.WithString("key", mcp.Description("Object key"), mcp.Required()),
		mcp.WithObject("metadata", mcp.Description("Object metadata as key-value pairs")),
	), t.UpdateObjectMetadata)

	mcpServer.AddTool(mcp.NewTool(ToolDeleteObject,
		mcp.WithDescription("Delete a specific object from a bucket"),
		mcp.WithString("bucket", mcp.Description("Name of the bucket containing the object"), mcp.Required()),
		mcp.WithString("key", mcp.Description("Object key"), mcp.Required()),
	), t.DeleteObject)

	mcpServer.AddTool(mcp.NewTool(ToolDownloadObject,
		mcp.WithDescription("Download object data with byte-offset pagination (max 10 MiB per request). For large files, use multiple requests with increasing offset. Data is base64-encoded. Use stat_object first to get file size."),
		mcp.WithString("bucket", mcp.Description("Name of the bucket containing the object"), mcp.Required()),
		mcp.WithString("key", mcp.Description("Object key"), mcp.Required()),
		mcp.WithNumber("offset", mcp.Description("Byte offset to start reading from"), mcp.Min(0), mcp.DefaultNumber(0)),
	), t.DownloadObject)

	mcpServer.AddTool(mcp.NewTool(ToolUploadObject,
		mcp.WithDescription("Upload an object. If the object is larger than 10 MiB, use multipart upload: begin_upload -> upload_part (multiple) -> commit_upload instead."),
		mcp.WithString("bucket", mcp.Description("Name of the bucket to upload to"), mcp.Required()),
		mcp.WithString("key", mcp.Description("Object key to upload"), mcp.Required()),
		mcp.WithString("data", mcp.Description("Base64 encoded object data"), mcp.MaxLength(maxDataSizeBase64), mcp.Required()),
	), t.UploadObject)

	// Register all multipart upload tools
	mcpServer.AddTool(mcp.NewTool(ToolListUploads,
		mcp.WithDescription("List uncommitted multipart uploads in a bucket with cursor-based pagination"),
		mcp.WithString("bucket", mcp.Description("Name of the bucket"), mcp.Required()),
		mcp.WithString("cursor", mcp.Description("Cursor for pagination"), mcp.DefaultString("")),
		mcp.WithNumber("limit", mcp.Description("Maximum number of uploads to return"), mcp.Min(1), mcp.Max(float64(maxUploadsLimit)), mcp.DefaultNumber(float64(maxUploadsLimit))),
	), t.ListUploads)

	mcpServer.AddTool(mcp.NewTool(ToolListUploadParts,
		mcp.WithDescription("List uploaded parts for a specific multipart upload"),
		mcp.WithString("bucket", mcp.Description("Name of the bucket"), mcp.Required()),
		mcp.WithString("key", mcp.Description("Object key"), mcp.Required()),
		mcp.WithString("uploadID", mcp.Description("Upload ID from begin_upload"), mcp.Required()),
	), t.ListUploadParts)

	mcpServer.AddTool(mcp.NewTool(ToolBeginUpload,
		mcp.WithDescription("Begin a new multipart upload"),
		mcp.WithString("bucket", mcp.Description("Name of the bucket"), mcp.Required()),
		mcp.WithString("key", mcp.Description("Object key"), mcp.Required()),
	), t.BeginUpload)

	mcpServer.AddTool(mcp.NewTool(ToolUploadPart,
		mcp.WithDescription("Upload a part of a multipart upload (max 10 MiB base64 encoded data). For large files: begin_upload -> upload_part (multiple) -> commit_upload. Part numbers start from 1."),
		mcp.WithString("bucket", mcp.Description("Name of the bucket"), mcp.Required()),
		mcp.WithString("key", mcp.Description("Object key"), mcp.Required()),
		mcp.WithString("uploadID", mcp.Description("Upload ID from begin_upload"), mcp.Required()),
		mcp.WithNumber("partNumber", mcp.Description("Part number (starting from 1)"), mcp.Min(1), mcp.Max(10000), mcp.Required()),
		mcp.WithString("data", mcp.Description("Base64 encoded part data"), mcp.MaxLength(maxDataSizeBase64), mcp.Required()),
	), t.UploadPart)

	mcpServer.AddTool(mcp.NewTool(ToolCommitUpload,
		mcp.WithDescription("Commit a multipart upload to complete the object"),
		mcp.WithString("bucket", mcp.Description("Name of the bucket"), mcp.Required()),
		mcp.WithString("key", mcp.Description("Object key"), mcp.Required()),
		mcp.WithString("uploadID", mcp.Description("Upload ID from begin_upload"), mcp.Required()),
		mcp.WithObject("metadata", mcp.Description("Optional object metadata as key-value pairs")),
	), t.CommitUpload)

	mcpServer.AddTool(mcp.NewTool(ToolAbortUpload,
		mcp.WithDescription("Abort a multipart upload and delete all uploaded parts"),
		mcp.WithString("bucket", mcp.Description("Name of the bucket"), mcp.Required()),
		mcp.WithString("key", mcp.Description("Object key"), mcp.Required()),
		mcp.WithString("uploadID", mcp.Description("Upload ID from begin_upload"), mcp.Required()),
	), t.AbortUpload)

	// Register file sharing tool
	mcpServer.AddTool(mcp.NewTool(ToolShareURL,
		mcp.WithDescription("Generate a public sharing URL for an object or prefix with optional time restriction. End key with '/' for folder sharing. Use expires in RFC3339 format. Generated URLs work without authentication."),
		mcp.WithString("bucket", mcp.Description("Name of the bucket"), mcp.Required()),
		mcp.WithString("key", mcp.Description("Object key or prefix (for prefix, end with '/' to enable listing)"), mcp.Required()),
		mcp.WithString("expires", mcp.Description("Optional expiration time in RFC3339 format (e.g., '2024-12-31T23:59:59Z')"), mcp.DefaultString("")),
		mcp.WithBoolean("allowListing", mcp.Description("Allow listing objects under the prefix (default: true for prefixes ending with '/')"), mcp.DefaultBool(true)),
	), t.ShareURL)
}

// ListBuckets implements the list_buckets MCP tool.
func (t *Tools) ListBuckets(ctx context.Context, request mcp.CallToolRequest) (_ *mcp.CallToolResult, err error) {
	defer mon.Task()(&ctx)(&err)

	project, _, err := t.parseCredentials(ctx, middleware.GetCredentials(ctx))
	if err != nil {
		return mcpToolError(credentialsErrorMessage(err))
	}
	defer func() { err = errs.Combine(err, project.Close()) }()

	cursor := mcp.ParseString(request, "cursor", "")
	limit := mcp.ParseInt(request, "limit", maxBucketsLimit)
	if limit < 1 || limit >= maxBucketsLimit {
		limit = maxBucketsLimit
	}

	options := uplink.ListBucketsOptions{
		Cursor: cursor,
	}

	it := project.ListBuckets(ctx, &options)
	var buckets []ListBucketsItem

	count := 0
	var nextCursor string
	for it.Next() && count < limit {
		bucket := it.Item()
		buckets = append(buckets, ListBucketsItem{
			Name:    bucket.Name,
			Created: bucket.Created.Format(time.RFC3339),
		})
		nextCursor = bucket.Name
		count++
	}

	if err = it.Err(); err != nil {
		return mcpToolError("Failed to list buckets: " + err.Error())
	}

	hasMore := it.Next()

	bucketNames := make([]string, len(buckets))
	for i, bucket := range buckets {
		bucketNames[i] = bucket.Name
	}

	var summary string
	if len(buckets) == 0 {
		summary = "No buckets found. Use create_bucket to create your first bucket."
	} else if len(buckets) == 1 {
		summary = fmt.Sprintf("Found 1 bucket: %s", bucketNames[0])
	} else {
		summary = fmt.Sprintf("Found %d buckets: %s", len(buckets), strings.Join(bucketNames, ", "))
	}

	if hasMore {
		summary += fmt.Sprintf(" (showing first %d, more available)", len(buckets))
	}

	resp := ListBucketsResponse{
		Summary:    summary,
		Buckets:    buckets,
		Count:      len(buckets),
		HasMore:    hasMore,
		NextCursor: "",
	}
	if hasMore && nextCursor != "" {
		resp.NextCursor = nextCursor
	}

	resultJSON, err := json.Marshal(&resp)
	if err != nil {
		return mcpToolError("Failed to marshal result: " + err.Error())
	}

	return mcp.NewToolResultText(string(resultJSON)), nil
}

// CreateBucket implements the create_bucket MCP tool.
func (t *Tools) CreateBucket(ctx context.Context, request mcp.CallToolRequest) (_ *mcp.CallToolResult, err error) {
	defer mon.Task()(&ctx)(&err)

	project, _, err := t.parseCredentials(ctx, middleware.GetCredentials(ctx))
	if err != nil {
		return mcpToolError(credentialsErrorMessage(err))
	}
	defer func() { err = errs.Combine(err, project.Close()) }()

	bucketName := mcp.ParseString(request, "bucket", "")
	if bucketName == "" {
		return mcpToolError("Bucket name is required")
	}

	if _, err = project.CreateBucket(ctx, bucketName); err != nil {
		return mcpToolError("Failed to create bucket: " + err.Error())
	}

	resultJSON, err := json.Marshal(&CreateBucketResponse{
		Summary: fmt.Sprintf("Successfully created bucket '%s'. You can now upload objects to this bucket using upload_part or copy objects from other buckets.", bucketName),
		Bucket:  bucketName,
		Status:  "created",
	})
	if err != nil {
		return mcpToolError("Failed to marshal result: " + err.Error())
	}

	return mcp.NewToolResultText(string(resultJSON)), nil
}

// DeleteBucket implements the delete_bucket MCP tool.
func (t *Tools) DeleteBucket(ctx context.Context, request mcp.CallToolRequest) (_ *mcp.CallToolResult, err error) {
	defer mon.Task()(&ctx)(&err)

	project, _, err := t.parseCredentials(ctx, middleware.GetCredentials(ctx))
	if err != nil {
		return mcpToolError(credentialsErrorMessage(err))
	}
	defer func() { err = errs.Combine(err, project.Close()) }()

	bucketName := mcp.ParseString(request, "bucket", "")
	if bucketName == "" {
		return mcpToolError("Bucket name is required")
	}

	if _, err = project.DeleteBucket(ctx, bucketName); err != nil {
		return mcpToolError("Failed to delete bucket: " + err.Error())
	}

	resultJSON, err := json.Marshal(&DeleteBucketResponse{
		Bucket: bucketName,
		Status: "deleted",
	})
	if err != nil {
		return mcpToolError("Failed to marshal result: " + err.Error())
	}

	return mcp.NewToolResultText(string(resultJSON)), nil
}

// DeleteBucketWithObjects implements the delete_bucket_with_objects MCP tool.
func (t *Tools) DeleteBucketWithObjects(ctx context.Context, request mcp.CallToolRequest) (_ *mcp.CallToolResult, err error) {
	defer mon.Task()(&ctx)(&err)

	project, _, err := t.parseCredentials(ctx, middleware.GetCredentials(ctx))
	if err != nil {
		return mcpToolError(credentialsErrorMessage(err))
	}
	defer func() { err = errs.Combine(err, project.Close()) }()

	bucketName := mcp.ParseString(request, "bucket", "")
	if bucketName == "" {
		return mcpToolError("Bucket name is required")
	}

	if _, err = project.DeleteBucketWithObjects(ctx, bucketName); err != nil {
		return mcpToolError("Failed to delete bucket with objects: " + err.Error())
	}

	resultJSON, err := json.Marshal(&DeleteBucketWithObjectsResponse{
		Bucket: bucketName,
		Status: "deleted",
	})
	if err != nil {
		return mcpToolError("Failed to marshal result: " + err.Error())
	}

	return mcp.NewToolResultText(string(resultJSON)), nil
}

// EnsureBucket implements the ensure_bucket MCP tool.
func (t *Tools) EnsureBucket(ctx context.Context, request mcp.CallToolRequest) (_ *mcp.CallToolResult, err error) {
	defer mon.Task()(&ctx)(&err)

	project, _, err := t.parseCredentials(ctx, middleware.GetCredentials(ctx))
	if err != nil {
		return mcpToolError(credentialsErrorMessage(err))
	}
	defer func() { err = errs.Combine(err, project.Close()) }()

	bucketName := mcp.ParseString(request, "bucket", "")
	if bucketName == "" {
		return mcpToolError("Bucket name is required")
	}

	bucket, err := project.EnsureBucket(ctx, bucketName)
	if err != nil {
		return mcpToolError("Failed to ensure bucket: " + err.Error())
	}

	resultJSON, err := json.Marshal(&EnsureBucketResponse{
		Bucket:  bucket.Name,
		Created: bucket.Created.Format(time.RFC3339),
		Status:  "ensured",
	})
	if err != nil {
		return mcpToolError("Failed to marshal result: " + err.Error())
	}

	return mcp.NewToolResultText(string(resultJSON)), nil
}

// StatBucket implements the stat_bucket MCP tool.
func (t *Tools) StatBucket(ctx context.Context, request mcp.CallToolRequest) (_ *mcp.CallToolResult, err error) {
	defer mon.Task()(&ctx)(&err)

	project, _, err := t.parseCredentials(ctx, middleware.GetCredentials(ctx))
	if err != nil {
		return mcpToolError(credentialsErrorMessage(err))
	}
	defer func() { err = errs.Combine(err, project.Close()) }()

	bucketName := mcp.ParseString(request, "bucket", "")
	if bucketName == "" {
		return mcpToolError("Bucket name is required")
	}

	bucket, err := project.StatBucket(ctx, bucketName)
	if err != nil {
		return mcpToolError("Failed to stat bucket: " + err.Error())
	}

	resultJSON, err := json.Marshal(&StatBucketResponse{
		Name:    bucket.Name,
		Created: bucket.Created.Format(time.RFC3339),
	})
	if err != nil {
		return mcpToolError("Failed to marshal result: " + err.Error())
	}

	return mcp.NewToolResultText(string(resultJSON)), nil
}

// ListObjects implements the list_objects MCP tool.
func (t *Tools) ListObjects(ctx context.Context, request mcp.CallToolRequest) (_ *mcp.CallToolResult, err error) {
	defer mon.Task()(&ctx)(&err)

	project, _, err := t.parseCredentials(ctx, middleware.GetCredentials(ctx))
	if err != nil {
		return mcpToolError(credentialsErrorMessage(err))
	}
	defer func() { err = errs.Combine(err, project.Close()) }()

	bucketName := mcp.ParseString(request, "bucket", "")
	if bucketName == "" {
		return mcpToolError("Bucket name is required")
	}

	prefix := mcp.ParseString(request, "prefix", "")
	cursor := mcp.ParseString(request, "cursor", "")
	limit := mcp.ParseInt(request, "limit", maxObjectsLimit)
	if limit < 0 || limit >= maxObjectsLimit {
		limit = maxObjectsLimit
	}

	it := project.ListObjects(ctx, bucketName, &uplink.ListObjectsOptions{
		Prefix: prefix,
		Cursor: cursor,
		System: true,
	})
	var objects []ListObjectsItem

	count := 0
	var nextCursor string
	for it.Next() && count < limit {
		object := it.Item()
		objects = append(objects, ListObjectsItem{
			Key:      object.Key,
			Size:     object.System.ContentLength,
			Modified: object.System.Created.Format(time.RFC3339),
		})
		nextCursor = object.Key
		count++
	}

	if err = it.Err(); err != nil {
		return mcpToolError("Failed to list objects: " + err.Error())
	}

	hasMore := it.Next()

	var summary string
	if len(objects) == 0 {
		if prefix == "" {
			summary = fmt.Sprintf("No objects found in bucket '%s'. Use upload_object or multipart (begin_upload -> upload_part -> commit_object) to add objects.", bucketName)
		} else {
			summary = fmt.Sprintf("No objects found in bucket '%s' with prefix '%s'.", bucketName, prefix)
		}
	} else {
		if prefix == "" {
			summary = fmt.Sprintf("Found %d objects in bucket '%s'", len(objects), bucketName)
		} else {
			summary = fmt.Sprintf("Found %d objects in bucket '%s' with prefix '%s'", len(objects), bucketName, prefix)
		}
		if hasMore {
			summary += fmt.Sprintf(" (showing first %d, more available)", len(objects))
		}
	}

	resp := ListObjectsResponse{
		Summary:    summary,
		Bucket:     bucketName,
		Prefix:     prefix,
		Objects:    objects,
		Count:      len(objects),
		HasMore:    hasMore,
		NextCursor: "",
	}
	if hasMore && nextCursor != "" {
		resp.NextCursor = nextCursor
	}

	resultJSON, err := json.Marshal(&resp)
	if err != nil {
		return mcpToolError("Failed to marshal result: " + err.Error())
	}

	return mcp.NewToolResultText(string(resultJSON)), nil
}

// MoveObject implements the move_object MCP tool.
func (t *Tools) MoveObject(ctx context.Context, request mcp.CallToolRequest) (_ *mcp.CallToolResult, err error) {
	defer mon.Task()(&ctx)(&err)

	project, _, err := t.parseCredentials(ctx, middleware.GetCredentials(ctx))
	if err != nil {
		return mcpToolError(credentialsErrorMessage(err))
	}
	defer func() { err = errs.Combine(err, project.Close()) }()

	srcBucket := mcp.ParseString(request, "srcBucket", "")
	srcKey := mcp.ParseString(request, "srcKey", "")
	destBucket := mcp.ParseString(request, "destBucket", "")
	destKey := mcp.ParseString(request, "destKey", "")

	if srcBucket == "" || srcKey == "" || destBucket == "" || destKey == "" {
		return mcpToolError("Source bucket, source key, destination bucket, and destination key are required")
	}

	if err = project.MoveObject(ctx, srcBucket, srcKey, destBucket, destKey, nil); err != nil {
		return mcpToolError("Failed to move object: " + err.Error())
	}

	resultJSON, err := json.Marshal(&MoveObjectResponse{
		SrcBucket:  srcBucket,
		SrcKey:     srcKey,
		DestBucket: destBucket,
		DestKey:    destKey,
		Status:     "moved",
	})
	if err != nil {
		return mcpToolError("Failed to marshal result: " + err.Error())
	}

	return mcp.NewToolResultText(string(resultJSON)), nil
}

// CopyObject implements the copy_object MCP tool.
func (t *Tools) CopyObject(ctx context.Context, request mcp.CallToolRequest) (_ *mcp.CallToolResult, err error) {
	defer mon.Task()(&ctx)(&err)

	project, _, err := t.parseCredentials(ctx, middleware.GetCredentials(ctx))
	if err != nil {
		return mcpToolError(credentialsErrorMessage(err))
	}
	defer func() { err = errs.Combine(err, project.Close()) }()

	srcBucket := mcp.ParseString(request, "srcBucket", "")
	srcKey := mcp.ParseString(request, "srcKey", "")
	destBucket := mcp.ParseString(request, "destBucket", "")
	destKey := mcp.ParseString(request, "destKey", "")

	if srcBucket == "" || srcKey == "" || destBucket == "" || destKey == "" {
		return mcpToolError("Source bucket, source key, destination bucket, and destination key are required")
	}

	if _, err = project.CopyObject(ctx, srcBucket, srcKey, destBucket, destKey, nil); err != nil {
		return mcpToolError("Failed to copy object: " + err.Error())
	}

	resultJSON, err := json.Marshal(&CopyObjectResponse{
		SrcBucket:  srcBucket,
		SrcKey:     srcKey,
		DestBucket: destBucket,
		DestKey:    destKey,
		Status:     "copied",
	})
	if err != nil {
		return mcpToolError("Failed to marshal result: " + err.Error())
	}

	return mcp.NewToolResultText(string(resultJSON)), nil
}

// StatObject implements the stat_object MCP tool.
func (t *Tools) StatObject(ctx context.Context, request mcp.CallToolRequest) (_ *mcp.CallToolResult, err error) {
	defer mon.Task()(&ctx)(&err)

	project, _, err := t.parseCredentials(ctx, middleware.GetCredentials(ctx))
	if err != nil {
		return mcpToolError(credentialsErrorMessage(err))
	}
	defer func() { err = errs.Combine(err, project.Close()) }()

	bucketName := mcp.ParseString(request, "bucket", "")
	key := mcp.ParseString(request, "key", "")

	if bucketName == "" || key == "" {
		return mcpToolError("Bucket name and key are required")
	}

	object, err := project.StatObject(ctx, bucketName, key)
	if err != nil {
		return mcpToolError("Failed to stat object: " + err.Error())
	}

	sizeStr := formatSize(object.System.ContentLength)

	resultJSON, err := json.Marshal(&StatObjectResponse{
		Summary:  fmt.Sprintf("Object %s/%s: %s, modified %s", bucketName, object.Key, sizeStr, object.System.Created.Format("2006-01-02 15:04:05")),
		Bucket:   bucketName,
		Key:      object.Key,
		Size:     object.System.ContentLength,
		Modified: object.System.Created.Format(time.RFC3339),
		Metadata: object.Custom,
	})
	if err != nil {
		return mcpToolError("Failed to marshal result: " + err.Error())
	}

	return mcp.NewToolResultText(string(resultJSON)), nil
}

// UpdateObjectMetadata implements the update_object_metadata MCP tool.
func (t *Tools) UpdateObjectMetadata(ctx context.Context, request mcp.CallToolRequest) (_ *mcp.CallToolResult, err error) {
	defer mon.Task()(&ctx)(&err)

	project, _, err := t.parseCredentials(ctx, middleware.GetCredentials(ctx))
	if err != nil {
		return mcpToolError(credentialsErrorMessage(err))
	}
	defer func() { err = errs.Combine(err, project.Close()) }()

	bucketName := mcp.ParseString(request, "bucket", "")
	key := mcp.ParseString(request, "key", "")

	if bucketName == "" || key == "" {
		return mcpToolError("Bucket name and key are required")
	}

	var metadata map[string]string
	if metadataArg := mcp.ParseArgument(request, "metadata", nil); metadataArg != nil {
		if metadataMap, ok := metadataArg.(map[string]any); ok {
			metadata = make(map[string]string)
			for k, v := range metadataMap {
				if strVal, ok := v.(string); ok {
					metadata[k] = strVal
				}
			}
		}
	}

	if err = project.UpdateObjectMetadata(ctx, bucketName, key, metadata, nil); err != nil {
		return mcpToolError("Failed to update object metadata: " + err.Error())
	}

	resultJSON, err := json.Marshal(&UpdateObjectMetadataResponse{
		Bucket:   bucketName,
		Key:      key,
		Metadata: metadata,
		Status:   "updated",
	})
	if err != nil {
		return mcpToolError("Failed to marshal result: " + err.Error())
	}

	return mcp.NewToolResultText(string(resultJSON)), nil
}

// DeleteObject implements the delete_object MCP tool.
func (t *Tools) DeleteObject(ctx context.Context, request mcp.CallToolRequest) (_ *mcp.CallToolResult, err error) {
	defer mon.Task()(&ctx)(&err)

	project, _, err := t.parseCredentials(ctx, middleware.GetCredentials(ctx))
	if err != nil {
		return mcpToolError(credentialsErrorMessage(err))
	}
	defer func() { err = errs.Combine(err, project.Close()) }()

	bucketName := mcp.ParseString(request, "bucket", "")
	key := mcp.ParseString(request, "key", "")

	if bucketName == "" || key == "" {
		return mcpToolError("Bucket name and key are required")
	}

	if _, err = project.DeleteObject(ctx, bucketName, key); err != nil {
		return mcpToolError("Failed to delete object: " + err.Error())
	}

	resultJSON, err := json.Marshal(&DeleteObjectResponse{
		Bucket: bucketName,
		Key:    key,
		Status: "deleted",
	})
	if err != nil {
		return mcpToolError("Failed to marshal result: " + err.Error())
	}

	return mcp.NewToolResultText(string(resultJSON)), nil
}

// DownloadObject implements the download_object MCP tool with byte-offset pagination.
func (t *Tools) DownloadObject(ctx context.Context, request mcp.CallToolRequest) (_ *mcp.CallToolResult, err error) {
	defer mon.Task()(&ctx)(&err)

	project, _, err := t.parseCredentials(ctx, middleware.GetCredentials(ctx))
	if err != nil {
		return mcpToolError(credentialsErrorMessage(err))
	}
	defer func() { err = errs.Combine(err, project.Close()) }()

	bucketName := mcp.ParseString(request, "bucket", "")
	key := mcp.ParseString(request, "key", "")

	if bucketName == "" || key == "" {
		return mcpToolError("Bucket name and key are required")
	}

	offset := mcp.ParseInt(request, "offset", 0)
	maxChunkSize := int64(maxDataSize)

	objectInfo, err := project.StatObject(ctx, bucketName, key)
	if err != nil {
		return mcpToolError("Failed to stat object: " + err.Error())
	}

	totalSize := objectInfo.System.ContentLength
	if int64(offset) >= totalSize {
		return mcpToolError("Offset exceeds object size")
	}

	remainingBytes := totalSize - int64(offset)
	chunkSize := min(remainingBytes, maxChunkSize)

	download, err := project.DownloadObject(ctx, bucketName, key, &uplink.DownloadOptions{
		Offset: int64(offset),
		Length: chunkSize,
	})
	if err != nil {
		return mcpToolError("Failed to start download: " + err.Error())
	}
	defer func() { err = errs.Combine(err, download.Close()) }()

	data, err := io.ReadAll(download)
	if err != nil {
		return mcpToolError("Failed to read object data: " + err.Error())
	}

	encodedData := base64.StdEncoding.EncodeToString(data)
	nextOffset := int64(offset) + int64(len(data))
	hasMore := nextOffset < totalSize
	progress := float64(nextOffset) / float64(totalSize) * 100
	summary := fmt.Sprintf("Downloaded %d bytes from %s/%s (%.1f%% complete)", len(data), bucketName, key, progress)
	if hasMore {
		summary += fmt.Sprintf(". Use offset %d to download the next chunk.", nextOffset)
	} else {
		summary += ". Download complete."
	}

	resp := DownloadObjectResponse{
		Summary:    summary,
		Bucket:     bucketName,
		Key:        key,
		Data:       encodedData,
		Offset:     int64(offset),
		Length:     len(data),
		TotalSize:  totalSize,
		HasMore:    hasMore,
		Encoding:   "Base64-encoded binary data",
		NextOffset: nextOffset,
	}
	if hasMore {
		resp.NextAction = fmt.Sprintf("Use download_object with offset=%d to get the next chunk", nextOffset)
	}

	resultJSON, err := json.Marshal(&resp)
	if err != nil {
		return mcpToolError("Failed to marshal result: " + err.Error())
	}

	return mcp.NewToolResultText(string(resultJSON)), nil
}

// UploadObject implements the upload_object MCP tool for small objects.
func (t *Tools) UploadObject(ctx context.Context, request mcp.CallToolRequest) (_ *mcp.CallToolResult, err error) {
	defer mon.Task()(&ctx)(&err)

	project, _, err := t.parseCredentials(ctx, middleware.GetCredentials(ctx))
	if err != nil {
		return mcpToolError(credentialsErrorMessage(err))
	}
	defer func() { err = errs.Combine(err, project.Close()) }()

	bucketName := mcp.ParseString(request, "bucket", "")
	key := mcp.ParseString(request, "key", "")
	dataStr := mcp.ParseString(request, "data", "")

	if bucketName == "" || key == "" || dataStr == "" {
		return mcpToolError("Bucket name, key, and data are required")
	}

	data, err := base64.StdEncoding.DecodeString(dataStr)
	if err != nil {
		return mcpToolError("Failed to decode base64 data: " + err.Error())
	}

	upload, err := project.UploadObject(ctx, bucketName, key, nil)
	if err != nil {
		return mcpToolError("Failed to upload object: " + err.Error())
	}

	_, err = sync2.Copy(ctx, upload, bytes.NewBuffer(data))
	if err != nil {
		_ = upload.Abort()
		return mcpToolError("Failed to upload data: " + err.Error())
	}

	if err = upload.Commit(); err != nil {
		return mcpToolError("Failed to commit upload: " + err.Error())
	}

	resultJSON, err := json.Marshal(&UploadObjectResponse{
		Summary: fmt.Sprintf("Successfully uploaded object %s/%s (%d bytes)", bucketName, key, len(data)),
		Bucket:  bucketName,
		Key:     key,
		Status:  "uploaded",
	})
	if err != nil {
		return mcpToolError("Failed to marshal result: " + err.Error())
	}

	return mcp.NewToolResultText(string(resultJSON)), nil
}

// ListUploads implements the list_uploads MCP tool.
func (t *Tools) ListUploads(ctx context.Context, request mcp.CallToolRequest) (_ *mcp.CallToolResult, err error) {
	defer mon.Task()(&ctx)(&err)

	project, _, err := t.parseCredentials(ctx, middleware.GetCredentials(ctx))
	if err != nil {
		return mcpToolError(credentialsErrorMessage(err))
	}
	defer func() { err = errs.Combine(err, project.Close()) }()

	bucketName := mcp.ParseString(request, "bucket", "")
	if bucketName == "" {
		return mcpToolError("Bucket name is required")
	}

	cursor := mcp.ParseString(request, "cursor", "")
	limit := mcp.ParseInt(request, "limit", maxUploadsLimit)
	if limit < 1 || limit >= maxUploadsLimit {
		limit = maxUploadsLimit
	}

	it := project.ListUploads(ctx, bucketName, &uplink.ListUploadsOptions{
		Cursor: cursor,
		System: true,
	})
	var uploads []ListUploadsItem

	count := 0
	var nextCursor string
	for it.Next() && count < limit {
		upload := it.Item()
		uploads = append(uploads, ListUploadsItem{
			UploadID: upload.UploadID,
			Key:      upload.Key,
			Created:  upload.System.Created.Format(time.RFC3339),
			Metadata: upload.Custom,
		})
		nextCursor = upload.Key
		count++
	}

	if err = it.Err(); err != nil {
		return mcpToolError("Failed to list uploads: " + err.Error())
	}

	hasMore := it.Next()

	resp := ListUploadsResponse{
		Bucket:     bucketName,
		Uploads:    uploads,
		Count:      len(uploads),
		HasMore:    hasMore,
		NextCursor: "",
	}
	if hasMore && nextCursor != "" {
		resp.NextCursor = nextCursor
	}

	resultJSON, err := json.Marshal(&resp)
	if err != nil {
		return mcpToolError("Failed to marshal result: " + err.Error())
	}

	return mcp.NewToolResultText(string(resultJSON)), nil
}

// ListUploadParts implements the list_upload_parts MCP tool.
func (t *Tools) ListUploadParts(ctx context.Context, request mcp.CallToolRequest) (_ *mcp.CallToolResult, err error) {
	defer mon.Task()(&ctx)(&err)

	project, _, err := t.parseCredentials(ctx, middleware.GetCredentials(ctx))
	if err != nil {
		return mcpToolError(credentialsErrorMessage(err))
	}
	defer func() { err = errs.Combine(err, project.Close()) }()

	bucketName := mcp.ParseString(request, "bucket", "")
	key := mcp.ParseString(request, "key", "")
	uploadID := mcp.ParseString(request, "uploadID", "")

	if bucketName == "" || key == "" || uploadID == "" {
		return mcpToolError("Bucket name, key, and uploadID are required")
	}

	it := project.ListUploadParts(ctx, bucketName, key, uploadID, nil)
	var parts []ListUploadPartsItem

	for it.Next() {
		part := it.Item()
		parts = append(parts, ListUploadPartsItem{
			PartNumber: part.PartNumber,
			Size:       part.Size,
			Modified:   part.Modified.Format(time.RFC3339),
			ETag:       string(part.ETag),
		})
	}

	if err := it.Err(); err != nil {
		return mcpToolError("Failed to list upload parts: " + err.Error())
	}

	resultJSON, err := json.Marshal(&ListUploadPartsResponse{
		Bucket:   bucketName,
		Key:      key,
		UploadID: uploadID,
		Parts:    parts,
		Count:    len(parts),
	})
	if err != nil {
		return mcpToolError("Failed to marshal result: " + err.Error())
	}

	return mcp.NewToolResultText(string(resultJSON)), nil
}

// BeginUpload implements the begin_upload MCP tool.
func (t *Tools) BeginUpload(ctx context.Context, request mcp.CallToolRequest) (_ *mcp.CallToolResult, err error) {
	defer mon.Task()(&ctx)(&err)

	project, _, err := t.parseCredentials(ctx, middleware.GetCredentials(ctx))
	if err != nil {
		return mcpToolError(credentialsErrorMessage(err))
	}
	defer func() { err = errs.Combine(err, project.Close()) }()

	bucketName := mcp.ParseString(request, "bucket", "")
	key := mcp.ParseString(request, "key", "")

	if bucketName == "" || key == "" {
		return mcpToolError("Bucket name and key are required")
	}

	var options uplink.UploadOptions

	uploadInfo, err := project.BeginUpload(ctx, bucketName, key, &options)
	if err != nil {
		return mcpToolError("Failed to begin upload: " + err.Error())
	}

	resultJSON, err := json.Marshal(&BeginUploadResponse{
		Summary:  fmt.Sprintf("Started multipart upload for %s/%s. Use upload_part to upload data chunks, then commit_upload to complete.", bucketName, key),
		Bucket:   bucketName,
		Key:      key,
		UploadID: uploadInfo.UploadID,
		Status:   "started",
		NextStep: "Use upload_part with this uploadID to upload data chunks",
	})
	if err != nil {
		return mcpToolError("Failed to marshal result: " + err.Error())
	}

	return mcp.NewToolResultText(string(resultJSON)), nil
}

// UploadPart implements the upload_part MCP tool.
func (t *Tools) UploadPart(ctx context.Context, request mcp.CallToolRequest) (_ *mcp.CallToolResult, err error) {
	defer mon.Task()(&ctx)(&err)

	project, _, err := t.parseCredentials(ctx, middleware.GetCredentials(ctx))
	if err != nil {
		return mcpToolError(credentialsErrorMessage(err))
	}
	defer func() { err = errs.Combine(err, project.Close()) }()

	bucketName := mcp.ParseString(request, "bucket", "")
	key := mcp.ParseString(request, "key", "")
	uploadID := mcp.ParseString(request, "uploadID", "")
	partNumber := mcp.ParseInt(request, "partNumber", 0)
	dataStr := mcp.ParseString(request, "data", "")

	if bucketName == "" || key == "" || uploadID == "" || partNumber == 0 || dataStr == "" {
		return mcpToolError("Bucket name, key, uploadID, partNumber, and data are required")
	}

	data, err := base64.StdEncoding.DecodeString(dataStr)
	if err != nil {
		return mcpToolError("Failed to decode base64 data: " + err.Error())
	}

	upload, err := project.UploadPart(ctx, bucketName, key, uploadID, uint32(partNumber))
	if err != nil {
		return mcpToolError("Failed to start part upload: " + err.Error())
	}

	_, err = sync2.Copy(ctx, upload, bytes.NewBuffer(data))
	if err != nil {
		_ = upload.Abort()
		return mcpToolError("Failed to upload part data: " + err.Error())
	}

	if err = upload.Commit(); err != nil {
		return mcpToolError("Failed to commit part: " + err.Error())
	}

	resultJSON, err := json.Marshal(&UploadPartResponse{
		Summary:    fmt.Sprintf("Successfully uploaded part %d (%d bytes) for %s/%s. Use commit_upload to complete the multipart upload.", partNumber, len(data), bucketName, key),
		Bucket:     bucketName,
		Key:        key,
		UploadID:   uploadID,
		PartNumber: partNumber,
		Size:       len(data),
		Status:     "uploaded",
		Encoding:   "Binary data was base64 decoded before upload",
	})
	if err != nil {
		return mcpToolError("Failed to marshal result: " + err.Error())
	}

	return mcp.NewToolResultText(string(resultJSON)), nil
}

// CommitUpload implements the commit_upload MCP tool.
func (t *Tools) CommitUpload(ctx context.Context, request mcp.CallToolRequest) (_ *mcp.CallToolResult, err error) {
	defer mon.Task()(&ctx)(&err)

	project, _, err := t.parseCredentials(ctx, middleware.GetCredentials(ctx))
	if err != nil {
		return mcpToolError(credentialsErrorMessage(err))
	}
	defer func() { err = errs.Combine(err, project.Close()) }()

	bucketName := mcp.ParseString(request, "bucket", "")
	key := mcp.ParseString(request, "key", "")
	uploadID := mcp.ParseString(request, "uploadID", "")

	if bucketName == "" || key == "" || uploadID == "" {
		return mcpToolError("Bucket name, key, and uploadID are required")
	}

	var metadata map[string]string
	if metadataArg := mcp.ParseArgument(request, "metadata", nil); metadataArg != nil {
		if metadataMap, ok := metadataArg.(map[string]any); ok {
			metadata = make(map[string]string)
			for k, v := range metadataMap {
				if strVal, ok := v.(string); ok {
					metadata[k] = strVal
				}
			}
		}
	}

	options := uplink.CommitUploadOptions{
		CustomMetadata: metadata,
	}

	object, err := project.CommitUpload(ctx, bucketName, key, uploadID, &options)
	if err != nil {
		return mcpToolError("Failed to commit upload: " + err.Error())
	}

	sizeStr := formatSize(object.System.ContentLength)

	resultJSON, err := json.Marshal(&CommitUploadResponse{
		Summary:  fmt.Sprintf("Successfully completed multipart upload for %s/%s. Final size: %s", bucketName, key, sizeStr),
		Bucket:   bucketName,
		Key:      key,
		UploadID: uploadID,
		Size:     object.System.ContentLength,
		Created:  object.System.Created.Format(time.RFC3339),
		Status:   "completed",
		NextStep: "Object is now available for download or sharing",
	})
	if err != nil {
		return mcpToolError("Failed to marshal result: " + err.Error())
	}

	return mcp.NewToolResultText(string(resultJSON)), nil
}

// AbortUpload implements the abort_upload MCP tool.
func (t *Tools) AbortUpload(ctx context.Context, request mcp.CallToolRequest) (_ *mcp.CallToolResult, err error) {
	defer mon.Task()(&ctx)(&err)

	project, _, err := t.parseCredentials(ctx, middleware.GetCredentials(ctx))
	if err != nil {
		return mcpToolError(credentialsErrorMessage(err))
	}
	defer func() { err = errs.Combine(err, project.Close()) }()

	bucketName := mcp.ParseString(request, "bucket", "")
	key := mcp.ParseString(request, "key", "")
	uploadID := mcp.ParseString(request, "uploadID", "")

	if bucketName == "" || key == "" || uploadID == "" {
		return mcpToolError("Bucket name, key, and uploadID are required")
	}

	if err = project.AbortUpload(ctx, bucketName, key, uploadID); err != nil {
		return mcpToolError("Failed to abort upload: " + err.Error())
	}

	resultJSON, err := json.Marshal(&AbortUploadResponse{
		Bucket:   bucketName,
		Key:      key,
		UploadID: uploadID,
		Status:   "aborted",
	})
	if err != nil {
		return mcpToolError("Failed to marshal result: " + err.Error())
	}

	return mcp.NewToolResultText(string(resultJSON)), nil
}

// ShareURL implements the share_url MCP tool for generating public sharing URLs.
func (t *Tools) ShareURL(ctx context.Context, request mcp.CallToolRequest) (_ *mcp.CallToolResult, err error) {
	defer mon.Task()(&ctx)(&err)

	project, access, err := t.parseCredentials(ctx, middleware.GetCredentials(ctx))
	if err != nil {
		return mcpToolError(credentialsErrorMessage(err))
	}
	defer func() { err = errs.Combine(err, project.Close()) }()

	bucketName := mcp.ParseString(request, "bucket", "")
	key := mcp.ParseString(request, "key", "")
	expiresStr := mcp.ParseString(request, "expires", "")
	allowListing := mcp.ParseBoolean(request, "allowListing", true)

	if bucketName == "" || key == "" {
		return mcpToolError("Bucket name and key are required")
	}

	// Parse expiration time if provided
	var expiration *time.Time
	if expiresStr != "" {
		parsedTime, err := time.Parse(time.RFC3339, expiresStr)
		if err != nil {
			return mcpToolError("Invalid expires time format. Use RFC3339 format (e.g., '2024-12-31T23:59:59Z')")
		}
		expiration = &parsedTime
	}

	// Determine if this is a prefix (ends with '/') or specific object
	isPrefix := strings.HasSuffix(key, "/")

	// Create appropriate permission based on whether listing is allowed
	var permission uplink.Permission
	if isPrefix && allowListing {
		// For prefixes with listing enabled, use full read permission
		permission = uplink.ReadOnlyPermission()
	} else {
		// For specific objects or prefixes without listing, use download-only permission
		permission = uplink.Permission{
			AllowDownload: true,
			AllowList:     false,
			AllowDelete:   false,
			AllowUpload:   false,
		}
	}

	if expiration != nil {
		permission.NotAfter = *expiration
	}

	// Create a share with the restricted permission for the specific object
	share, err := access.Share(permission, uplink.SharePrefix{
		Bucket: bucketName,
		Prefix: key,
	})
	if err != nil {
		return mcpToolError("Failed to create share: " + err.Error())
	}

	serializedAccess, err := share.Serialize()
	if err != nil {
		return mcpToolError("Failed to serialize access: " + err.Error())
	}

	// Register the access grant with authservice and get a sharing URL.
	creds, err := register.Access(ctx, t.config.AuthServiceURL, serializedAccess, true, nil)
	if err != nil {
		return mcpToolError("Failed to register access: " + err.Error())
	}
	shareURL, err := edge.JoinShareURL(t.config.LinkSharingURL, creds.AccessKeyID, bucketName, key, &edge.ShareURLOptions{
		Raw: false,
	})
	if err != nil {
		return mcpToolError("Failed to generate share URL: " + err.Error())
	}

	// Create human-readable summary
	var summary string
	if isPrefix {
		if allowListing {
			summary = fmt.Sprintf("Generated public sharing URL for folder '%s' in bucket '%s' with listing enabled", key, bucketName)
		} else {
			summary = fmt.Sprintf("Generated public sharing URL for folder '%s' in bucket '%s' (listing disabled)", key, bucketName)
		}
	} else {
		summary = fmt.Sprintf("Generated public sharing URL for object '%s' in bucket '%s'", key, bucketName)
	}

	if expiration != nil {
		summary += fmt.Sprintf(". URL expires on %s", expiration.Format("2006-01-02 15:04:05"))
	} else {
		summary += ". URL does not expire"
	}

	resp := ShareURLResponse{
		Summary:      summary,
		Bucket:       bucketName,
		Key:          key,
		ShareURL:     shareURL,
		IsPrefix:     isPrefix,
		AllowListing: isPrefix && allowListing,
		Usage:        "This URL can be accessed by anyone without authentication",
	}
	if expiration != nil {
		resp.Expires = expiration.Format(time.RFC3339)
	}

	resultJSON, err := json.Marshal(&resp)
	if err != nil {
		return mcpToolError("Failed to marshal result: " + err.Error())
	}

	return mcp.NewToolResultText(string(resultJSON)), nil
}

func (t *Tools) parseCredentials(ctx context.Context, credentials *middleware.Credentials) (_ *uplink.Project, _ *uplink.Access, err error) {
	if credentials == nil {
		return nil, nil, errUnauthorized
	}

	config := uplink.Config{
		UserAgent: userAgent,
	}

	if err = transport.SetSatelliteConnectionPool(ctx, &config, t.satelliteConnectionPool); err != nil {
		return nil, nil, err
	}
	if err = transport.SetConnectionPool(ctx, &config, t.connectionPool); err != nil {
		return nil, nil, err
	}

	access, err := uplink.ParseAccess(credentials.AccessGrant)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse access: %w", err)
	}

	project, err := config.OpenProject(ctx, access)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open project: %w", err)
	}

	return project, access, nil
}

// formatSize formats a byte size into a human-readable string.
func formatSize(size int64) string {
	if size < 1024 {
		return fmt.Sprintf("%d B", size)
	} else if size < 1024*1024 {
		return fmt.Sprintf("%.1f KiB", float64(size)/1024)
	} else if size < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MiB", float64(size)/1024/1024)
	} else {
		return fmt.Sprintf("%.1f GiB", float64(size)/1024/1024/1024)
	}
}

// mcpToolError is a helper function that wraps MCP tool errors
// This helps bypass nilerr linting checks when returning MCP errors with nil Go errors
func mcpToolError(message string) (*mcp.CallToolResult, error) {
	return mcp.NewToolResultError(message), nil
}

// credentialsErrorMessage provides a user message based on credential errors. If the
// error isn't one of missing credentials it may be internal to uplink, so write a
// generic message in that case.
func credentialsErrorMessage(err error) string {
	if errs.Is(err, errUnauthorized) {
		return "Unauthorized"
	}
	return "Failed to parse credentials"
}
