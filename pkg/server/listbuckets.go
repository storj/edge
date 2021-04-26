// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package server

import (
	"context"
	"net/http"

	"github.com/storj/minio/pkg/storj/model"

	"storj.io/uplink"
)

// ListBuckets https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html
func (s *Server) ListBuckets(w http.ResponseWriter, r *http.Request) {
	s.WithProject(w, r, func(ctx context.Context, p *uplink.Project) error {
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
			return err
		}
		response.Buckets.Buckets = buckets

		body, err := model.Encode("application/xml", response)
		if err != nil {
			return err
		}
		_, err = w.Write(body)
		return err
	})
}
