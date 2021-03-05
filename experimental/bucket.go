// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/storj/gateway-mt/experimental/middleware/project"
	"github.com/storj/minio/pkg/storj/model"
)

// ListBuckets https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html
func (h *Handler) ListBuckets(w http.ResponseWriter, r *http.Request) {
	fmt.Println("ListBuckets", r)

	ctx := r.Context()

	p := project.GetUplinkProject(ctx)

	response := &model.ListBucketsResponse{}

	buckets := []model.Bucket{}

	bi := p.ListBuckets(ctx, nil)
	for bi.Next() {
		item := bi.Item()
		bucket := model.Bucket{
			Name:         item.Name,
			CreationDate: model.ISO8601(item.Created),
		}
		buckets = append(buckets, bucket)
	}
	if err := bi.Err(); err != nil {
		model.Error{
			Err:    err,
			Status: 500,
		}.ServeHTTP(w, r)

		return
	}
	response.Buckets.Buckets = buckets

	body, err := model.Encode("application/xml", response)
	if err != nil {
		model.Error{
			Err:    err,
			Status: 500,
		}.ServeHTTP(w, r)

		return
	}

	w.Write(body)
}

// CreateBucket https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html
func (h *Handler) CreateBucket(w http.ResponseWriter, r *http.Request) {
	fmt.Println("CreateBucket", r)

	ctx := r.Context()

	p := project.GetUplinkProject(ctx)

	bucket := mux.Vars(r)["bucket"]

	_, err := p.CreateBucket(ctx, bucket)
	if err != nil {
		model.Error{
			Err:    err,
			Status: 500,
		}.ServeHTTP(w, r)

		return
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusCreated)
}

// HeadBucket https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadBucket.html
func (h *Handler) HeadBucket(w http.ResponseWriter, r *http.Request) {
	fmt.Println("HeadBucket", r)

	ctx := r.Context()

	p := project.GetUplinkProject(ctx)

	bucket := mux.Vars(r)["bucket"]

	_, err := p.StatBucket(ctx, bucket)
	if err != nil {
		model.Error{
			Err:    err,
			Status: http.StatusNotFound,
		}.ServeHTTP(w, r)

		return
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusNoContent)
}

// DeleteBucket https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucket.html
func (h *Handler) DeleteBucket(w http.ResponseWriter, r *http.Request) {
	fmt.Println("DeleteBucket", r)

	ctx := r.Context()

	p := project.GetUplinkProject(ctx)

	bucket := mux.Vars(r)["bucket"]

	_, err := p.DeleteBucket(ctx, bucket)
	if err != nil {
		model.Error{
			Err:    err,
			Status: 500,
		}.ServeHTTP(w, r)

		return
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusNoContent)
}
