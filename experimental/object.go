// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"fmt"
	"net/http"
)

// ListObjects https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjects.html
func (h *Handler) ListObjects(w http.ResponseWriter, r *http.Request) {
	fmt.Println("ListObjects", r)
}

// ListObjectsV2 https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html
func (h *Handler) ListObjectsV2(w http.ResponseWriter, r *http.Request) {
	fmt.Println("ListObjectsV2", r)
}

// PutObject https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html
func (h *Handler) PutObject(w http.ResponseWriter, r *http.Request) {
	fmt.Println("PutObject", r)
}

// HeadObject https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html
func (h *Handler) HeadObject(w http.ResponseWriter, r *http.Request) {
	fmt.Println("HeadObject", r)
}

// GetObject https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html
func (h *Handler) GetObject(w http.ResponseWriter, r *http.Request) {
	fmt.Println("GetObject", r)
}

// DeleteObject https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObject.html
func (h *Handler) DeleteObject(w http.ResponseWriter, r *http.Request) {
	fmt.Println("DeleteObject", r)
}
