// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"go.uber.org/zap"

	"storj.io/common/sync2"
	"storj.io/edge/pkg/errdata"
	"storj.io/uplink"
)

// handleHostingService deals with linksharing via custom URLs.
func (handler *Handler) handleHostingService(ctx context.Context, w http.ResponseWriter, r *http.Request) (err error) {
	defer mon.Task()(&ctx)(&err)

	creds := credentialsFromContext(ctx)
	if creds.err != nil {
		return creds.err
	}

	// Redirect to HTTPS only custom domains with `storj-tls:true` TXT record
	if handler.redirectHTTPS && r.TLS == nil && creds.hostingTLS {
		target := url.URL{Scheme: "https", Host: r.Host, Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery}
		http.Redirect(w, r, target.String(), http.StatusPermanentRedirect)
		return nil
	}

	bucket, key := determineBucketAndObjectKey(creds.hostingRoot, r.URL.Path)

	project, err := handler.uplink.OpenProject(ctx, creds.access)
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
		access:          creds.access,
		bucket:          bucket,
		realKey:         key,
		visibleKey:      visibleKey,
		title:           creds.hostingHost,
		root:            breadcrumb{Prefix: creds.hostingHost, URL: "/"},
		wrapDefault:     false,
		downloadDefault: false,
		hosting:         true,
		hostingTLS:      creds.hostingTLS,
	}, project)

	// if the error is anything other than ObjectNotFound, return to normal
	// error handling. this includes the err == nil case
	if !errors.Is(err, uplink.ErrObjectNotFound) {
		return err
	}

	// in ObjectNotFound, let the user provide a custom 404 page

	bucket, key = determineBucketAndObjectKey(creds.hostingRoot, "/404.html")
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
	_, err = sync2.Copy(ctx, w, download)
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
