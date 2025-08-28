// Copyright (C) 2025 Storj Labs, Inc.
// See LICENSE for copying information.

package tools

// ListBucketsResponse is a response from the list_buckets tool.
type ListBucketsResponse struct {
	Summary    string            `json:"summary"`
	Buckets    []ListBucketsItem `json:"buckets"`
	Count      int               `json:"count"`
	HasMore    bool              `json:"hasMore"`
	NextCursor string            `json:"nextCursor,omitempty"`
}

// ListBucketsItem is a response item for a bucket in ListBucketsResponse.
type ListBucketsItem struct {
	Name    string `json:"name"`
	Created string `json:"created"`
}

// CreateBucketResponse is a response from the create_bucket tool.
type CreateBucketResponse struct {
	Summary string `json:"summary"`
	Bucket  string `json:"bucket"`
	Status  string `json:"status"`
}

// DeleteBucketResponse is a response from the delete_bucket tool.
type DeleteBucketResponse struct {
	Bucket string `json:"bucket"`
	Status string `json:"status"`
}

// DeleteBucketWithObjectsResponse is a response from the delete_bucket_with_objects tool.
type DeleteBucketWithObjectsResponse struct {
	Bucket string `json:"bucket"`
	Status string `json:"status"`
}

// EnsureBucketResponse is a response from the ensure_bucket tool.
type EnsureBucketResponse struct {
	Bucket  string `json:"bucket"`
	Created string `json:"created"`
	Status  string `json:"status"`
}

// StatBucketResponse is a response from the stat_bucket tool.
type StatBucketResponse struct {
	Name    string `json:"name"`
	Created string `json:"created"`
}

// ListObjectsResponse is a response from the list_objects tool.
type ListObjectsResponse struct {
	Summary    string            `json:"summary"`
	Bucket     string            `json:"bucket"`
	Prefix     string            `json:"prefix"`
	Objects    []ListObjectsItem `json:"objects"`
	Count      int               `json:"count"`
	HasMore    bool              `json:"hasMore"`
	NextCursor string            `json:"nextCursor,omitempty"`
}

// ListObjectsItem is a response item for an object in ListObjectsResponse.
type ListObjectsItem struct {
	Key      string `json:"key"`
	Size     int64  `json:"size"`
	Modified string `json:"modified"`
}

// MoveObjectResponse is a response from the move_object tool.
type MoveObjectResponse struct {
	SrcBucket  string `json:"srcBucket"`
	SrcKey     string `json:"srcKey"`
	DestBucket string `json:"destBucket"`
	DestKey    string `json:"destKey"`
	Status     string `json:"status"`
}

// CopyObjectResponse is a response from the copy_object tool.
type CopyObjectResponse struct {
	SrcBucket  string `json:"srcBucket"`
	SrcKey     string `json:"srcKey"`
	DestBucket string `json:"destBucket"`
	DestKey    string `json:"destKey"`
	Status     string `json:"status"`
}

// StatObjectResponse is a response from the stat_object tool.
type StatObjectResponse struct {
	Summary  string            `json:"summary"`
	Bucket   string            `json:"bucket"`
	Key      string            `json:"key"`
	Size     int64             `json:"size"`
	Modified string            `json:"modified"`
	Metadata map[string]string `json:"metadata"`
}

// UpdateObjectMetadataResponse is a response from the update_object_metadata tool.
type UpdateObjectMetadataResponse struct {
	Bucket   string            `json:"bucket"`
	Key      string            `json:"key"`
	Metadata map[string]string `json:"metadata"`
	Status   string            `json:"status"`
}

// DeleteObjectResponse is a response from the delete_object tool.
type DeleteObjectResponse struct {
	Bucket string `json:"bucket"`
	Key    string `json:"key"`
	Status string `json:"status"`
}

// DownloadObjectResponse is a response from the download_object tool.
type DownloadObjectResponse struct {
	Summary    string `json:"summary"`
	Bucket     string `json:"bucket"`
	Key        string `json:"key"`
	Data       string `json:"data"`
	Offset     int64  `json:"offset"`
	Length     int    `json:"length"`
	TotalSize  int64  `json:"totalSize"`
	HasMore    bool   `json:"hasMore"`
	Encoding   string `json:"encoding"`
	NextOffset int64  `json:"nextOffset,omitempty"`
	NextAction string `json:"nextAction,omitempty"`
}

// UploadObjectResponse is a response from the upload_object tool.
type UploadObjectResponse struct {
	Summary string `json:"summary"`
	Bucket  string `json:"bucket"`
	Key     string `json:"key"`
	Status  string `json:"status"`
}

// ListUploadsResponse is a response from the list_uploads tool.
type ListUploadsResponse struct {
	Bucket     string            `json:"bucket"`
	Uploads    []ListUploadsItem `json:"uploads"`
	Count      int               `json:"count"`
	HasMore    bool              `json:"hasMore"`
	NextCursor string            `json:"nextCursor,omitempty"`
}

// ListUploadsItem is a response item for an upload in ListUploadsResponse.
type ListUploadsItem struct {
	UploadID string            `json:"uploadID"`
	Key      string            `json:"key"`
	Created  string            `json:"created"`
	Metadata map[string]string `json:"metadata"`
}

// ListUploadPartsResponse is a response from the list_upload_parts tool.
type ListUploadPartsResponse struct {
	Bucket   string                `json:"bucket"`
	Key      string                `json:"key"`
	UploadID string                `json:"uploadID"`
	Parts    []ListUploadPartsItem `json:"parts"`
	Count    int                   `json:"count"`
}

// ListUploadPartsItem is a response item for a part in ListUploadPartsResponse.
type ListUploadPartsItem struct {
	PartNumber uint32 `json:"partNumber"`
	Size       int64  `json:"size"`
	Modified   string `json:"modified"`
	ETag       string `json:"etag"`
}

// BeginUploadResponse is a response from the begin_upload tool.
type BeginUploadResponse struct {
	Summary  string `json:"summary"`
	Bucket   string `json:"bucket"`
	Key      string `json:"key"`
	UploadID string `json:"uploadID"`
	Status   string `json:"status"`
	NextStep string `json:"nextStep"`
}

// UploadPartResponse is a response from the upload_part tool.
type UploadPartResponse struct {
	Summary    string `json:"summary"`
	Bucket     string `json:"bucket"`
	Key        string `json:"key"`
	UploadID   string `json:"uploadID"`
	PartNumber int    `json:"partNumber"`
	Size       int    `json:"size"`
	Status     string `json:"status"`
	Encoding   string `json:"encoding"`
}

// CommitUploadResponse is a response from the commit_upload tool.
type CommitUploadResponse struct {
	Summary  string `json:"summary"`
	Bucket   string `json:"bucket"`
	Key      string `json:"key"`
	UploadID string `json:"uploadID"`
	Size     int64  `json:"size"`
	Created  string `json:"created"`
	Status   string `json:"status"`
	NextStep string `json:"nextStep"`
}

// AbortUploadResponse is a response from the abort_upload tool.
type AbortUploadResponse struct {
	Bucket   string `json:"bucket"`
	Key      string `json:"key"`
	UploadID string `json:"uploadID"`
	Status   string `json:"status"`
}

// ShareURLResponse is a response from the share_url tool.
type ShareURLResponse struct {
	Summary      string `json:"summary"`
	Bucket       string `json:"bucket"`
	Key          string `json:"key"`
	ShareURL     string `json:"shareURL"`
	IsPrefix     bool   `json:"isPrefix"`
	AllowListing bool   `json:"allowListing"`
	Usage        string `json:"usage"`
	Expires      string `json:"expires,omitempty"`
}
