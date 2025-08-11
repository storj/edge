// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package mcpclient

import (
	"context"
	"encoding/json"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/zeebo/errs"

	"storj.io/edge/pkg/mcp-server/tools"
)

// Error is a class of mcp-client errors.
var Error = errs.Class("mcp-client")

// Client is used to interact with MCP tools.
type Client struct {
	c *client.Client
}

// New creates a new Client.
func New(serverURL, bearerToken string) (*Client, error) {
	transport, err := transport.NewStreamableHTTP(
		serverURL,
		transport.WithHTTPHeaders(map[string]string{
			"Authorization": "Bearer " + bearerToken,
		}),
	)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	c := client.NewClient(transport)

	_, err = c.Initialize(context.Background(), mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
		},
	})
	if err != nil {
		return nil, Error.Wrap(err)
	}

	return &Client{c: c}, nil
}

// ListBucketsRequest is a type of request to list buckets.
type ListBucketsRequest struct {
	Cursor string `json:"cursor"`
	Limit  int    `json:"limit,omitempty"`
}

// ListBuckets calls the list_buckets tool to retrieve a list of buckets.
func (c *Client) ListBuckets(ctx context.Context, req ListBucketsRequest) (*tools.ListBucketsResponse, error) {
	message, err := c.callTool(ctx, tools.ToolListBuckets, req)
	if err != nil {
		return nil, err
	}
	var resp tools.ListBucketsResponse
	if err := json.Unmarshal([]byte(message), &resp); err != nil {
		return nil, Error.New("failed to unmarshal response: %w", err)
	}
	return &resp, nil
}

// CreateBucketRequest is a type of request to create a new bucket.
type CreateBucketRequest struct {
	Bucket string `json:"bucket"`
}

// CreateBucket calls the create_bucket tool to create a new bucket.
func (c *Client) CreateBucket(ctx context.Context, req CreateBucketRequest) (*tools.CreateBucketResponse, error) {
	message, err := c.callTool(ctx, tools.ToolCreateBucket, req)
	if err != nil {
		return nil, err
	}
	var resp tools.CreateBucketResponse
	if err := json.Unmarshal([]byte(message), &resp); err != nil {
		return nil, Error.New("failed to unmarshal response: %w", err)
	}
	return &resp, nil
}

// DeleteBucketRequest is a type of request to delete a bucket.
type DeleteBucketRequest struct {
	Bucket string `json:"bucket"`
}

// DeleteBucket calls the delete_bucket tool to delete a bucket.
func (c *Client) DeleteBucket(ctx context.Context, req DeleteBucketRequest) (*tools.DeleteBucketResponse, error) {
	message, err := c.callTool(ctx, tools.ToolDeleteBucket, req)
	if err != nil {
		return nil, err
	}
	var resp tools.DeleteBucketResponse
	if err := json.Unmarshal([]byte(message), &resp); err != nil {
		return nil, Error.New("failed to unmarshal response: %w", err)
	}
	return &resp, nil
}

// DeleteBucketWithObjectsRequest is a type of request to delete a bucket along with it's objects.
type DeleteBucketWithObjectsRequest struct {
	Bucket string `json:"bucket"`
}

// DeleteBucketWithObjects calls the delete_bucket_with_objects tool to delete a bucket and its objects.
func (c *Client) DeleteBucketWithObjects(ctx context.Context, req DeleteBucketWithObjectsRequest) (*tools.DeleteBucketWithObjectsResponse, error) {
	message, err := c.callTool(ctx, tools.ToolDeleteBucketWithObjects, req)
	if err != nil {
		return nil, err
	}
	var resp tools.DeleteBucketWithObjectsResponse
	if err := json.Unmarshal([]byte(message), &resp); err != nil {
		return nil, Error.New("failed to unmarshal response: %w", err)
	}
	return &resp, nil
}

// EnsureBucketRequest is a type of request to ensure a bucket exists.
type EnsureBucketRequest struct {
	Bucket string `json:"bucket"`
}

// EnsureBucket calls the ensure_bucket tool to ensure a bucket exists.
func (c *Client) EnsureBucket(ctx context.Context, req EnsureBucketRequest) (*tools.EnsureBucketResponse, error) {
	message, err := c.callTool(ctx, tools.ToolEnsureBucket, req)
	if err != nil {
		return nil, err
	}
	var resp tools.EnsureBucketResponse
	if err := json.Unmarshal([]byte(message), &resp); err != nil {
		return nil, Error.New("failed to unmarshal response: %w", err)
	}
	return &resp, nil
}

// StatBucketRequest is a type of request to get information about a bucket.
type StatBucketRequest struct {
	Bucket string `json:"bucket"`
}

// StatBucket calls the stat_bucket tool to retrieve information about a bucket.
func (c *Client) StatBucket(ctx context.Context, req StatBucketRequest) (*tools.StatBucketResponse, error) {
	message, err := c.callTool(ctx, tools.ToolStatBucket, req)
	if err != nil {
		return nil, err
	}
	var resp tools.StatBucketResponse
	if err := json.Unmarshal([]byte(message), &resp); err != nil {
		return nil, Error.New("failed to unmarshal response: %w", err)
	}
	return &resp, nil
}

// ListObjectsRequest is a type of request to list objects in a bucket.
type ListObjectsRequest struct {
	Bucket string `json:"bucket"`
	Prefix string `json:"prefix"`
	Cursor string `json:"cursor"`
	Limit  int    `json:"limit,omitempty"`
}

// ListObjects calls the list_objects tool to retrieve a list of objects in a bucket.
func (c *Client) ListObjects(ctx context.Context, req ListObjectsRequest) (*tools.ListObjectsResponse, error) {
	message, err := c.callTool(ctx, tools.ToolListObjects, req)
	if err != nil {
		return nil, err
	}
	var resp tools.ListObjectsResponse
	if err := json.Unmarshal([]byte(message), &resp); err != nil {
		return nil, Error.New("failed to unmarshal response: %w", err)
	}
	return &resp, nil
}

// MoveObjectRequest is a type of request to move an object from one bucket to another.
type MoveObjectRequest struct {
	SrcBucket  string `json:"srcBucket"`
	SrcKey     string `json:"srcKey"`
	DestBucket string `json:"destBucket"`
	DestKey    string `json:"destKey"`
}

// MoveObject calls the move_object tool to move an object.
func (c *Client) MoveObject(ctx context.Context, req MoveObjectRequest) (*tools.MoveObjectResponse, error) {
	message, err := c.callTool(ctx, tools.ToolMoveObject, req)
	if err != nil {
		return nil, err
	}
	var resp tools.MoveObjectResponse
	if err := json.Unmarshal([]byte(message), &resp); err != nil {
		return nil, Error.New("failed to unmarshal response: %w", err)
	}
	return &resp, nil
}

// CopyObjectRequest is a type of request to copy an object from one bucket to another.
type CopyObjectRequest struct {
	SrcBucket  string `json:"srcBucket"`
	SrcKey     string `json:"srcKey"`
	DestBucket string `json:"destBucket"`
	DestKey    string `json:"destKey"`
}

// CopyObject calls the copy_object tool to copy an object.
func (c *Client) CopyObject(ctx context.Context, req CopyObjectRequest) (*tools.CopyObjectResponse, error) {
	message, err := c.callTool(ctx, tools.ToolCopyObject, req)
	if err != nil {
		return nil, err
	}
	var resp tools.CopyObjectResponse
	if err := json.Unmarshal([]byte(message), &resp); err != nil {
		return nil, Error.New("failed to unmarshal response: %w", err)
	}
	return &resp, nil
}

// StatObjectRequest is a type of request to get information about an object.
type StatObjectRequest struct {
	Bucket string `json:"bucket"`
	Key    string `json:"key"`
}

// StatObject calls the stat_object tool to retrieve information about an object.
func (c *Client) StatObject(ctx context.Context, req StatObjectRequest) (*tools.StatObjectResponse, error) {
	message, err := c.callTool(ctx, tools.ToolStatObject, req)
	if err != nil {
		return nil, err
	}
	var resp tools.StatObjectResponse
	if err := json.Unmarshal([]byte(message), &resp); err != nil {
		return nil, Error.New("failed to unmarshal response: %w", err)
	}
	return &resp, nil
}

// UpdateObjectMetadataRequest is a type of request to update metadata of an object.
type UpdateObjectMetadataRequest struct {
	Bucket   string            `json:"bucket"`
	Key      string            `json:"key"`
	Metadata map[string]string `json:"metadata"`
}

// UpdateObjectMetadata calls the update_object_metadata tool to update metadata of an object.
func (c *Client) UpdateObjectMetadata(ctx context.Context, req UpdateObjectMetadataRequest) (*tools.UpdateObjectMetadataResponse, error) {
	message, err := c.callTool(ctx, tools.ToolUpdateObjectMetadata, req)
	if err != nil {
		return nil, err
	}
	var resp tools.UpdateObjectMetadataResponse
	if err := json.Unmarshal([]byte(message), &resp); err != nil {
		return nil, Error.New("failed to unmarshal response: %w", err)
	}
	return &resp, nil
}

// DeleteObjectRequest is a type of request to delete an object.
type DeleteObjectRequest struct {
	Bucket string `json:"bucket"`
	Key    string `json:"key"`
}

// DeleteObject calls the delete_object tool to delete an object.
func (c *Client) DeleteObject(ctx context.Context, req DeleteObjectRequest) (*tools.DeleteObjectResponse, error) {
	message, err := c.callTool(ctx, tools.ToolDeleteObject, req)
	if err != nil {
		return nil, err
	}
	var resp tools.DeleteObjectResponse
	if err := json.Unmarshal([]byte(message), &resp); err != nil {
		return nil, Error.New("failed to unmarshal response: %w", err)
	}
	return &resp, nil
}

// DownloadObjectRequest is a type of request to download an object.
type DownloadObjectRequest struct {
	Bucket string `json:"bucket"`
	Key    string `json:"key"`
	Offset int64  `json:"offset,omitempty"`
}

// DownloadObject calls the download_object tool to download an object.
func (c *Client) DownloadObject(ctx context.Context, req DownloadObjectRequest) (*tools.DownloadObjectResponse, error) {
	message, err := c.callTool(ctx, tools.ToolDownloadObject, req)
	if err != nil {
		return nil, err
	}
	var resp tools.DownloadObjectResponse
	if err := json.Unmarshal([]byte(message), &resp); err != nil {
		return nil, Error.New("failed to unmarshal response: %w", err)
	}
	return &resp, nil
}

// UploadObjectRequest is a type of request to upload an object.
type UploadObjectRequest struct {
	Bucket string `json:"bucket"`
	Key    string `json:"key"`
	Data   string `json:"data"`
}

// UploadObject calls the upload_object tool to upload an object.
func (c *Client) UploadObject(ctx context.Context, req UploadObjectRequest) (*tools.UploadObjectResponse, error) {
	message, err := c.callTool(ctx, tools.ToolUploadObject, req)
	if err != nil {
		return nil, err
	}
	var resp tools.UploadObjectResponse
	if err := json.Unmarshal([]byte(message), &resp); err != nil {
		return nil, Error.New("failed to unmarshal response: %w", err)
	}
	return &resp, nil
}

// ListUploadsRequest is a type of request to list uploads in a bucket.
type ListUploadsRequest struct {
	Bucket string `json:"bucket"`
	Cursor string `json:"cursor"`
	Limit  int    `json:"limit,omitempty"`
}

// ListUploads calls the list_uploads tool to retrieve a list of uploads in a bucket.
func (c *Client) ListUploads(ctx context.Context, req ListUploadsRequest) (*tools.ListUploadsResponse, error) {
	message, err := c.callTool(ctx, tools.ToolListUploads, req)
	if err != nil {
		return nil, err
	}
	var resp tools.ListUploadsResponse
	if err := json.Unmarshal([]byte(message), &resp); err != nil {
		return nil, Error.New("failed to unmarshal response: %w", err)
	}
	return &resp, nil
}

// ListUploadPartsRequest is a type of request to list parts of a multipart upload.
type ListUploadPartsRequest struct {
	Bucket   string `json:"bucket"`
	Key      string `json:"key"`
	UploadID string `json:"uploadID"`
}

// ListUploadParts calls the list_upload_parts tool to retrieve parts of a multipart upload.
func (c *Client) ListUploadParts(ctx context.Context, req ListUploadPartsRequest) (*tools.ListUploadPartsResponse, error) {
	message, err := c.callTool(ctx, tools.ToolListUploadParts, req)
	if err != nil {
		return nil, err
	}
	var resp tools.ListUploadPartsResponse
	if err := json.Unmarshal([]byte(message), &resp); err != nil {
		return nil, Error.New("failed to unmarshal response: %w", err)
	}
	return &resp, nil
}

// BeginUploadRequest is a type of request to begin a multipart upload.
type BeginUploadRequest struct {
	Bucket string `json:"bucket"`
	Key    string `json:"key"`
}

// BeginUpload calls the begin_upload tool to start a multipart upload.
func (c *Client) BeginUpload(ctx context.Context, req BeginUploadRequest) (*tools.BeginUploadResponse, error) {
	message, err := c.callTool(ctx, tools.ToolBeginUpload, req)
	if err != nil {
		return nil, err
	}
	var resp tools.BeginUploadResponse
	if err := json.Unmarshal([]byte(message), &resp); err != nil {
		return nil, Error.New("failed to unmarshal response: %w", err)
	}
	return &resp, nil
}

// UploadPartRequest is a type of request to upload a part of a multipart upload.
type UploadPartRequest struct {
	Bucket     string `json:"bucket"`
	Key        string `json:"key"`
	UploadID   string `json:"uploadID"`
	PartNumber int    `json:"partNumber"`
	Data       string `json:"data"`
}

// UploadPart calls the upload_part tool to upload a part of a multipart upload.
func (c *Client) UploadPart(ctx context.Context, req UploadPartRequest) (*tools.UploadPartResponse, error) {
	message, err := c.callTool(ctx, tools.ToolUploadPart, req)
	if err != nil {
		return nil, err
	}
	var resp tools.UploadPartResponse
	if err := json.Unmarshal([]byte(message), &resp); err != nil {
		return nil, Error.New("failed to unmarshal response: %w", err)
	}
	return &resp, nil
}

// CommitUploadRequest is a type of request to commit a multipart upload.
type CommitUploadRequest struct {
	Bucket   string            `json:"bucket"`
	Key      string            `json:"key"`
	UploadID string            `json:"uploadID"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// CommitUpload calls the commit_upload tool to finalize a multipart upload.
func (c *Client) CommitUpload(ctx context.Context, req CommitUploadRequest) (*tools.CommitUploadResponse, error) {
	message, err := c.callTool(ctx, tools.ToolCommitUpload, req)
	if err != nil {
		return nil, err
	}
	var resp tools.CommitUploadResponse
	if err := json.Unmarshal([]byte(message), &resp); err != nil {
		return nil, Error.New("failed to unmarshal response: %w", err)
	}
	return &resp, nil
}

// AbortUploadRequest is a type of request to abort a multipart upload.
type AbortUploadRequest struct {
	Bucket   string `json:"bucket"`
	Key      string `json:"key"`
	UploadID string `json:"uploadID"`
}

// AbortUpload calls the abort_upload tool to cancel a multipart upload.
func (c *Client) AbortUpload(ctx context.Context, req AbortUploadRequest) (*tools.AbortUploadResponse, error) {
	message, err := c.callTool(ctx, tools.ToolAbortUpload, req)
	if err != nil {
		return nil, err
	}
	var resp tools.AbortUploadResponse
	if err := json.Unmarshal([]byte(message), &resp); err != nil {
		return nil, Error.New("failed to unmarshal response: %w", err)
	}
	return &resp, nil
}

// ShareURLRequest is a type of request to create a shareable URL for an object.
type ShareURLRequest struct {
	Bucket       string `json:"bucket"`
	Key          string `json:"key"`
	Expires      string `json:"expires,omitempty"`
	AllowListing bool   `json:"allowListing"`
}

// ShareURL calls the share_url tool to create a shareable URL for an object.
func (c *Client) ShareURL(ctx context.Context, req ShareURLRequest) (*tools.ShareURLResponse, error) {
	message, err := c.callTool(ctx, tools.ToolShareURL, req)
	if err != nil {
		return nil, err
	}
	var resp tools.ShareURLResponse
	if err := json.Unmarshal([]byte(message), &resp); err != nil {
		return nil, Error.New("failed to unmarshal response: %w", err)
	}
	return &resp, nil
}

func (c *Client) callTool(ctx context.Context, name string, req any) (string, error) {
	args := make(map[string]any)
	jsonData, err := json.Marshal(req)
	if err != nil {
		return "", Error.Wrap(err)
	}
	if err := json.Unmarshal(jsonData, &args); err != nil {
		return "", Error.Wrap(err)
	}

	r, err := c.c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      name,
			Arguments: args,
		},
	})
	if err != nil {
		return "", Error.Wrap(err)
	}

	var message string
	if len(r.Content) > 0 {
		if text, ok := r.Content[0].(mcp.TextContent); ok {
			message = text.Text
		}
	}

	if r.IsError {
		return "", Error.New("tool call failed: %s", message)
	}

	return message, nil
}
