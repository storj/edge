// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"context"
	"encoding/hex"
	"errors"
	"mime"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/jtolio/eventkit"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/memory"
	"storj.io/common/ranger/httpranger"
	"storj.io/gateway-mt/pkg/errdata"
	"storj.io/gateway-mt/pkg/linksharing/objectranger"
	"storj.io/gateway-mt/pkg/trustedip"
	"storj.io/uplink"
	privateAccess "storj.io/uplink/private/access"
	"storj.io/zipper"
)

type parsedRequest struct {
	access           *uplink.Access
	serializedAccess string
	bucket           string
	realKey          string
	visibleKey       string
	title            string
	root             breadcrumb
	wrapDefault      bool
	downloadDefault  bool
	hosting          bool
}

func (handler *Handler) present(ctx context.Context, w http.ResponseWriter, r *http.Request, pr *parsedRequest) (err error) {
	defer mon.Task()(&ctx)(&err)

	project, err := handler.uplink.OpenProject(ctx, pr.access)
	if err != nil {
		return errdata.WithStatus(errdata.WithAction(err, "open project"), http.StatusBadRequest)
	}
	defer func() {
		if err := project.Close(); err != nil {
			handler.log.With(zap.Error(err)).Warn("unable to close project")
		}
	}()

	return handler.presentWithProject(ctx, w, r, pr, project)
}

func (handler *Handler) presentWithProject(ctx context.Context, w http.ResponseWriter, r *http.Request, pr *parsedRequest, project *uplink.Project) (err error) {
	defer mon.Task()(&ctx)(&err)

	ek.Event("present",
		eventkit.String("host", r.Host),
		eventkit.String("uri", r.RequestURI),
		eventkit.String("method", r.Method),
		eventkit.Bool("hosting", pr.hosting),
		eventkit.String("remote-ip", trustedip.GetClientIP(handler.trustedClientIPsList, r)),
		eventkit.String("macaroon-head", hex.EncodeToString(privateAccess.APIKey(pr.access).Head())))

	// first, kick off background index.html request, if appropriate. we do this
	// to cut down on sequential round trips.
	type statResult struct {
		obj *uplink.Object
		err error
	}
	// make sure indexResult is buffered because we might be throwing this
	// stat object result away entirely.
	indexResultCh := make(chan statResult, 1)

	if pr.realKey == "" || strings.HasSuffix(pr.realKey, "/") {
		go func() {
			obj, err := project.StatObject(ctx, pr.bucket, pr.realKey+"index.html")
			indexResultCh <- statResult{obj: obj, err: err}
		}()
	} else {
		// make sure we've always sent a result
		indexResultCh <- statResult{err: errs.New(
			"unreachable, index.html lookup incorrectly expected")}
	}

	if pr.realKey != "" { // there are no objects with the empty key
		o, err := project.StatObject(ctx, pr.bucket, pr.realKey)
		if err == nil {
			return handler.showObject(ctx, w, r, pr, project, o)
		}
		if !errors.Is(err, uplink.ErrObjectNotFound) {
			return errdata.WithAction(err, "stat object")
		}
		if !strings.HasSuffix(pr.realKey, "/") {
			objNotFoundErr := errdata.WithAction(err, "stat object")

			// s3 has interesting behavior, which is if the object doesn't exist
			// but is a prefix, it will issue a redirect to have a trailing slash.
			isPrefix, err := handler.isPrefix(ctx, project, pr)
			if err != nil {
				return err
			}

			if isPrefix {
				http.Redirect(w, r, r.URL.Path+"/", http.StatusSeeOther)
				return nil
			}

			return objNotFoundErr
		}
	}

	// due to the above logic, if we reach this, the key is either exactly "" or ends in a "/",
	// so we should be able to read the index.html StatObject channel
	indexResult := <-indexResultCh
	o, err := indexResult.obj, indexResult.err
	if err == nil {
		return handler.showObject(ctx, w, r, pr, project, o)
	}
	if !errors.Is(err, uplink.ErrObjectNotFound) {
		return errdata.WithAction(err, "stat object - index.html")
	}

	// special case for if the user requested a bucket but there's no trailing slash
	if !strings.HasSuffix(r.URL.Path, "/") {
		http.Redirect(w, r, r.URL.Path+"/", http.StatusSeeOther)
		return nil
	}

	return handler.servePrefix(ctx, w, project, pr, "")
}

func (handler *Handler) showObject(ctx context.Context, w http.ResponseWriter, r *http.Request, pr *parsedRequest, project *uplink.Project, o *uplink.Object) (err error) {
	defer mon.Task()(&ctx)(&err)

	q := r.URL.Query()

	mapOnly := queryFlagLookup(q, "map", false)

	// if someone provides the 'download' flag on or off, we do that, otherwise
	// we do what the downloadDefault was (based on the URL scope).
	download := queryFlagLookup(q, "download", pr.downloadDefault)
	// if we're not downloading, and someone provides the 'wrap' flag on or off,
	// we do that. otherwise, we *don't* wrap if someone provided the view flag
	// on, otherwise we fall back to what wrapDefault was.
	wrap := queryFlagLookup(q, "wrap", !queryFlagLookup(q, "view", !pr.wrapDefault))

	var archivePath string

	if len(q["path"]) > 0 {
		archivePath = q["path"][0]
	}

	if download {
		if len(archivePath) > 0 {
			w.Header().Set("Content-Disposition", "attachment; filename="+archivePath)
		} else {
			w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(o.Key))
		}
	}

	if (download || !wrap) && !mapOnly {
		if len(archivePath) > 0 { // handle zip archives
			handler.setHeaders(w, r, o.Custom, pr.hosting, archivePath)
			if len(r.Header.Get("Range")) > 0 { // prohibit range requests for archives for now
				return errdata.WithStatus(errs.New("Range header isn't compatible with path query"), http.StatusRequestedRangeNotSatisfiable)
			}
			acceptsGz := hasValue(r.Header, "Accept-Encoding", "gzip")
			ranger, isGz, err := handler.archiveRanger(ctx, project, pr.bucket, o.Key, archivePath, acceptsGz)
			if err != nil {
				return errdata.WithStatus(err, http.StatusUnsupportedMediaType)
			}
			if isGz {
				w.Header().Set("Content-Encoding", "gzip")
			}
			err = httpranger.ServeContent(ctx, w, r, o.Key, o.System.Created, ranger)
			if err != nil {
				return errdata.WithAction(err, "serve content")
			}
		} else {
			handler.setHeaders(w, r, o.Custom, pr.hosting, filepath.Base(o.Key))
			err = httpranger.ServeContent(ctx, w, r, o.Key, o.System.Created, objectranger.New(project, o, pr.bucket))
			if err != nil {
				return errdata.WithAction(err, "serve content")
			}
		}
		return nil
	}

	if archivePath == "/" {
		return handler.servePrefix(ctx, w, project, pr, archivePath)
	}

	locations, pieces, err := handler.getLocations(ctx, pr)
	if err != nil {
		return errdata.WithAction(err, "get locations")
	}

	if mapOnly {
		return handler.serveMap(ctx, w, locations, pieces, o, q)
	}

	var input struct {
		Key        string
		Size       string
		NodesCount int
	}

	input.NodesCount = len(locations)

	// TODO(artur): fix image preview paths when the corresponding image is in
	// the zip archive.
	twitterImage, ogImage := imagePreviewPath(pr.serializedAccess, pr.bucket, o.Key, o.System.ContentLength)

	data := pageData{
		TwitterImage: twitterImage,
		OgImage:      ogImage,
	}

	if len(archivePath) > 0 {
		zip, err := zipper.OpenPack(ctx, project, pr.bucket, o.Key)
		if err != nil {
			return errdata.WithStatus(err, http.StatusUnsupportedMediaType)
		}
		f, err := zip.FileInfo(ctx, archivePath)
		if err != nil {
			return err
		}
		input.Key = archivePath
		input.Size = memory.Size(f.Size).Base10String()
		data.ArchivePath = archivePath
	} else {
		input.Key = filepath.Base(o.Key)
		input.Size = memory.Size(o.System.ContentLength).Base10String()
		data.ShowViewContents = strings.HasSuffix(input.Key, ".zip")
	}

	data.Data = input
	data.Title = input.Key

	handler.renderTemplate(w, "single-object.html", data)

	return nil
}

func (handler *Handler) setHeaders(w http.ResponseWriter, r *http.Request, metadata map[string]string, hosting bool, filename string) {
	detectType := !hasValue(r.Header, "X-Content-Type-Options", "nosniff")
	contentType := contentType(filename, metadata, detectType)
	if contentType != "" {
		if !handler.standardViewsHTML && !hosting && strings.Contains(strings.ToLower(contentType), "html") {
			contentType = "text/plain"
		}
		w.Header().Set("Content-Type", contentType)
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}

	if !handler.standardRendersContent && !hosting {
		w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	}

	cacheControl := metadataHeaderValue(metadata, "Cache-Control")
	if cacheControl != "" {
		w.Header().Set("Cache-Control", cacheControl)
	}

	contentEncoding := metadataHeaderValue(metadata, "Content-Encoding")
	if contentEncoding != "" {
		w.Header().Set("Content-Encoding", contentEncoding)
	}
}

func (handler *Handler) isPrefix(ctx context.Context, project *uplink.Project, pr *parsedRequest) (_ bool, err error) {
	defer mon.Task()(&ctx)(&err)

	// we might not having listing permission. if this is the case, guess that
	// we're looking for an index.html and look for that.
	_, err = project.StatObject(ctx, pr.bucket, pr.realKey+"/index.html")
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, uplink.ErrObjectNotFound) {
		return false, errdata.WithAction(err, "prefix determination stat")
	}

	// we need to do a brief list to find out if this object is a prefix.
	it := project.ListObjects(ctx, pr.bucket, &uplink.ListObjectsOptions{
		Prefix:    pr.realKey + "/",
		Recursive: true, // this is actually easier on the database if we don't page more than once
	})
	isPrefix := it.Next() // are there any objects with this prefix?
	err = it.Err()
	if err != nil {
		if errors.Is(err, uplink.ErrPermissionDenied) {
			return false, nil
		}
		return false, errdata.WithAction(err, "prefix determination list")
	}
	return isPrefix, nil
}

// imagePreviewPath returns a path to the requested image object for Twitter
// (twitterImage) and Facebook (ogImage) if the object under key is an image,
// meets the size and file format criteria.
//
// The paths are intended to be used as previews for when linksharing URL is
// shared on these sites.
func imagePreviewPath(access, bucket, key string, size int64) (twitterImage, ogImage string) {
	previewPath := "/raw/" + access + "/" + bucket + "/" + key

	if access == "" { // hosting request
		previewPath = "/raw/" + bucket + "/" + key
	}

	twitterLimit, facebookLimit := memory.MB.Int64(), 5*memory.MB.Int64()

	switch strings.ToLower(filepath.Ext(key)) {
	case ".jpg", ".jpeg", ".png", ".gif":
		if size <= twitterLimit {
			twitterImage = previewPath
		}
		if size <= facebookLimit {
			ogImage = previewPath
		}
	case ".webp":
		if size <= twitterLimit {
			twitterImage = previewPath
		}
	}

	return twitterImage, ogImage
}

func metadataHeaderValue(metadata map[string]string, header string) string {
	// order of preference: canonical form (e.g. "Content-Type"), then
	// all lowercase, then any other case.
	if v, ok := metadata[http.CanonicalHeaderKey(header)]; ok {
		return v
	}
	if v, ok := metadata[strings.ToLower(header)]; ok {
		return v
	}
	for k, v := range metadata {
		if strings.EqualFold(k, header) {
			return v
		}
	}
	return ""
}

func contentType(key string, metadata map[string]string, detectType bool) (contentType string) {
	contentType = metadataHeaderValue(metadata, "Content-Type")

	if detectType {
		// AWS SDK does not automatically detect the content type and will set
		// content-type to either application/octet-stream or binary/octet-stream
		// if nothing was set explicitly when uploading an object.
		if contentType == "application/octet-stream" || contentType == "binary/octet-stream" {
			contentType = ""
		}

		if contentType == "" {
			return mime.TypeByExtension(filepath.Ext(key))
		}
	}

	return contentType
}

func hasValue(header http.Header, key, value string) bool {
	for _, v := range header.Values(key) {
		if strings.EqualFold(v, value) {
			return true
		}
	}
	return false
}
