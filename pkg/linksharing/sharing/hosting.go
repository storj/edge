// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"

	"go.uber.org/zap"

	"storj.io/gateway-mt/pkg/errdata"
	"storj.io/gateway-mt/pkg/trustedip"
	"storj.io/uplink"
)

// handleHostingService deals with linksharing via custom URLs.
func (handler *Handler) handleHostingService(ctx context.Context, w http.ResponseWriter, r *http.Request) (err error) {
	defer mon.Task()(&ctx)(&err)

	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		var aerr *net.AddrError
		if errors.As(err, &aerr) && aerr.Err == "missing port in address" {
			host = r.Host
		} else {
			return errdata.WithStatus(err, http.StatusBadRequest)
		}
	}

	access, root, _, err := handler.txtRecords.FetchAccessForHost(
		ctx, host, trustedip.GetClientIP(handler.trustedClientIPsList, r),
	)
	if err != nil {
		return errdata.WithAction(err, "fetch access")
	}

	bucket, key := determineBucketAndObjectKey(root, r.URL.Path)

	project, err := handler.uplink.OpenProject(ctx, access)
	if err != nil {
		return errdata.WithAction(err, "open project")
	}
	defer func() {
		if err := project.Close(); err != nil {
			handler.log.With(zap.Error(err)).Warn("unable to close project")
		}
	}()

	visibleKey := strings.TrimPrefix(r.URL.Path, "/")
	if visibleKey == "" {
		// special case: if someone is looking for http://sub.domain.tld/,
		// explicitly assume they shared a prefix and are looking for index.html
		key += "index.html"
	}

	err = handler.presentWithProject(ctx, w, r, &parsedRequest{
		access:          access,
		bucket:          bucket,
		realKey:         key,
		visibleKey:      visibleKey,
		title:           host,
		root:            breadcrumb{Prefix: host, URL: "/"},
		wrapDefault:     false,
		downloadDefault: false,
		hosting:         true,
	}, project)

	// if the error is anything other than ObjectNotFound, return to normal
	// error handling. this includes the err == nil case
	if !errors.Is(err, uplink.ErrObjectNotFound) {
		return err
	}

	// in ObjectNotFound, let the user provide a custom 404 page

	bucket, key = determineBucketAndObjectKey(root, "/404.html")
	download, err := project.DownloadObject(ctx, bucket, key, nil)
	if err != nil {
		// if this returns uplink.ErrObjectNotFound, then, that's still
		// the right error, and we should return it and return our normal
		// 404 page, so this is fine to just pass through.
		return errdata.WithAction(err, "download 404")
	}
	defer func() {
		if err := download.Close(); err != nil {
			handler.log.With(zap.Error(err)).Warn("unable to close 404 download")
		}
	}()

	w.WriteHeader(http.StatusNotFound)
	_, err = io.Copy(w, download)
	if err != nil {
		return errdata.WithAction(err, "serve 404")
	}
	return nil
}

// determineBucketAndObjectKey is a helper function to parse storj_root and the url into the bucket and object key.
// For example, we have http://mydomain.com/prefix2/index.html with storj_root:bucket1/prefix1/
// The root path will be [bucket1, prefix1/]. Our bucket is named bucket1.
// Since the url has a path of /prefix2/index.html and the second half of the root path is prefix1,
// we get an object key of prefix1/prefix2/index.html. To make this work, the first (and only the
// first) prefix slash from the URL is stripped. Additionally, to aid security, if there is a non-empty
// prefix, it will have a suffix slash added to it if no trailing slash exists. See
// TestDetermineBucketAndObjectKey for many examples.
func determineBucketAndObjectKey(root, urlPath string) (bucket, key string) {
	parts := strings.SplitN(root, "/", 2)
	bucket = parts[0]
	prefix := ""
	if len(parts) > 1 {
		prefix = parts[1]
	}
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return bucket, prefix + strings.TrimPrefix(urlPath, "/")
}
