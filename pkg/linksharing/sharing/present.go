// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"mime"
	"net/http"
	"net/textproto"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/macaroon"
	"storj.io/common/memory"
	"storj.io/common/ranger/httpranger"
	"storj.io/edge/pkg/errdata"
	"storj.io/edge/pkg/linksharing/objectranger"
	"storj.io/uplink"
	privateAccess "storj.io/uplink/private/access"
	"storj.io/zipper"
)

const (
	noContentCoding   = "identity"
	gzipContentCoding = "gzip"
)

var spaceReplacer = strings.NewReplacer(" ", "", "\t", "")

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
	hostingTLS       bool
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

	q := r.URL.Query()
	download := queryFlagLookup(q, "download", pr.downloadDefault)
	downloadKind := queryStringLookup(q, "download-kind", "zip")
	wrap := queryFlagLookup(q, "wrap", !queryFlagLookup(q, "view", !pr.wrapDefault))
	mapOnly := queryFlagLookup(q, "map", false)
	cursor := q.Get("cursor")
	var archivePath string

	if len(q["path"]) > 0 {
		archivePath = q["path"][0]
	}

	switch {
	case strings.HasSuffix(pr.realKey, "/"):
		// kick off background index.html request to cut down on sequential round trips.
		type statResult struct {
			obj *uplink.Object
			err error
		}
		// make sure indexResult is buffered because we might be throwing this
		// stat object result away entirely.
		indexResultCh := make(chan statResult, 1)
		go func() {
			obj, err := project.StatObject(ctx, pr.bucket, pr.realKey+"index.html")
			indexResultCh <- statResult{obj: obj, err: err}
		}()

		// object key with a trailing slash?
		o, err := project.StatObject(ctx, pr.bucket, pr.realKey)
		if err == nil {
			return handler.showObject(ctx, w, r, pr, project, o, nil, httpranger.HTTPRange{})
		}
		if !errors.Is(err, uplink.ErrObjectNotFound) {
			return errdata.WithAction(err, "stat object")
		}

		// index.html object?
		indexResult := <-indexResultCh
		o, err = indexResult.obj, indexResult.err
		if err == nil {
			return handler.showObject(ctx, w, r, pr, project, o, nil, httpranger.HTTPRange{})
		}
		if !errors.Is(err, uplink.ErrObjectNotFound) {
			return errdata.WithAction(err, "stat object - index.html")
		}

		// it might be a prefix
		if (download || !wrap) && !pr.hosting {
			return handler.downloadPrefix(ctx, w, project, pr, downloadKind)
		}
		return handler.servePrefix(ctx, w, project, pr, "", cursor)

	case pr.realKey != "":
		var objectErr error
		options, rangeErr := predictRange(r.Header.Get("Range"))
		// a rangeErr here does not always result in RangeNotSatisfiable so ignore it and
		// allow StatObject and ServeContent to handle all the edge cases.
		if (download || !wrap) && !mapOnly && len(archivePath) == 0 && rangeErr == nil {
			d, err := project.DownloadObject(ctx, pr.bucket, pr.realKey, options)
			if err == nil {
				defer func() {
					if err := d.Close(); err != nil {
						handler.log.Debug("couldn't close the download", zap.Error(err))
					}
				}()
				// set the actual offset and length
				httpRange := optionsToRange(d.Info().System.ContentLength, options)
				return handler.showObject(ctx, w, r, pr, project, d.Info(), d, httpRange)
			}
			objectErr = errdata.WithAction(err, "download object")
			if errors.Is(objectErr, uplink.ErrPermissionDenied) || errors.Is(objectErr, uplink.ErrBandwidthLimitExceeded) {
				return objectErr
			}
		}
		// wrap, mapOnly, archive requests, rangeErr, and DownloadObject errors
		if !errors.Is(objectErr, uplink.ErrObjectNotFound) {
			o, err := project.StatObject(ctx, pr.bucket, pr.realKey)
			if err == nil {
				return handler.showObject(ctx, w, r, pr, project, o, nil, httpranger.HTTPRange{})
			}
			if !errors.Is(err, uplink.ErrObjectNotFound) {
				return errdata.WithAction(err, "stat object")
			}
			objectErr = errdata.WithAction(err, "stat object")
		}

		// s3 has interesting behavior, which is if the object doesn't exist
		// but is a prefix, it will issue a redirect to have a trailing slash.
		isPrefix, err := handler.isPrefix(ctx, project, pr)
		if err != nil {
			return err
		}

		if isPrefix {
			u := r.URL
			u.Path += "/"

			http.Redirect(w, r, u.String(), http.StatusSeeOther)
			return nil
		}

		return objectErr
	// there are no objects with the empty key
	case pr.realKey == "":
		if pr.hosting {
			o, err := project.StatObject(ctx, pr.bucket, "index.html")
			if err == nil {
				return handler.showObject(ctx, w, r, pr, project, o, nil, httpranger.HTTPRange{})
			}
			if !errors.Is(err, uplink.ErrObjectNotFound) {
				return errdata.WithAction(err, "stat object - index.html")
			}
		}

		// special case for if the user requested a bucket but there's no trailing slash
		if !strings.HasSuffix(r.URL.Path, "/") {
			u := r.URL
			u.Path += "/"

			http.Redirect(w, r, u.String(), http.StatusSeeOther)
			return nil
		}
		if (download || !wrap) && !pr.hosting {
			return handler.downloadPrefix(ctx, w, project, pr, downloadKind)
		}
		return handler.servePrefix(ctx, w, project, pr, "", cursor)
	default:
		return errdata.WithAction(err, "unexpected case")
	}
}

func (handler *Handler) showObject(ctx context.Context, w http.ResponseWriter, r *http.Request, pr *parsedRequest, project *uplink.Project, o *uplink.Object, d *uplink.Download, httpRange httpranger.HTTPRange) (err error) {
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
			acceptsGz := isContentCodingAcceptable(gzipContentCoding, r.Header)
			if !acceptsGz && !isContentCodingAcceptable(noContentCoding, r.Header) {
				w.Header().Set("Accept-Encoding", fmt.Sprintf("%s, %s, *;q=0", gzipContentCoding, noContentCoding))
				return errdata.WithStatus(errs.New("Unsupported content coding"), http.StatusUnsupportedMediaType)
			}
			ranger, isGz, err := handler.archiveRanger(ctx, project, pr.bucket, o.Key, archivePath, acceptsGz)
			if err != nil {
				return errdata.WithStatus(err, http.StatusUnsupportedMediaType)
			}
			if isGz {
				w.Header().Set("Content-Encoding", gzipContentCoding)
			}
			err = httpranger.ServeContent(ctx, w, r, o.Key, o.System.Created, ranger)
			if err != nil {
				return errdata.WithAction(err, "serve content")
			}
		} else {
			handler.setHeaders(w, r, o.Custom, pr.hosting, filepath.Base(o.Key))
			err = httpranger.ServeContent(ctx, w, r, o.Key, o.System.Created, objectranger.New(project, o, d, httpRange, pr.bucket))
			if err != nil {
				return errdata.WithAction(err, "serve content")
			}
		}
		return nil
	}

	if archivePath == "/" {
		return handler.servePrefix(ctx, w, project, pr, archivePath, "")
	}

	locations, pieces, placementConstraint, err := handler.getLocations(ctx, pr.access, pr.bucket, o.Key)
	if err != nil {
		return errdata.WithAction(err, "get locations")
	}

	if mapOnly {
		return handler.serveMap(ctx, w, locations, pieces, o, q)
	}

	var input struct {
		Key          string
		Size         string
		NodesCount   int
		HasPlacement bool
		IsInline     bool
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
			if errors.Is(err, fs.ErrNotExist) {
				return uplink.ErrObjectNotFound
			}
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

	input.HasPlacement = placementConstraint != 0
	input.IsInline = input.NodesCount == 0

	data.Data = input
	data.Title = input.Key
	data.AllowDownload = handler.isDownloadAllowed(pr.access)

	handler.renderTemplate(w, "single-object.html", data)

	return nil
}

// isDownloadAllowed checks an access grant if it allows downloads.
func (handler *Handler) isDownloadAllowed(access *uplink.Access) bool {
	mac, err := macaroon.ParseMacaroon(privateAccess.APIKey(access).SerializeRaw())
	if err != nil {
		handler.log.With(zap.Error(err)).Debug("unable to parse macaroon")
		return false
	}
	for _, cavbuf := range mac.Caveats() {
		var cav macaroon.Caveat
		err := cav.UnmarshalBinary(cavbuf)
		if err != nil {
			handler.log.With(zap.Error(err)).Debug("unable to unmarshal caveat")
			return false
		}
		if cav.DisallowReads {
			return false
		}
	}
	return true
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

	if !handler.standardRendersContent && !allowedInlineType(contentType) && !hosting {
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
	previewPath, err := url.JoinPath("raw", access, bucket, key)
	if err != nil {
		return "", ""
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

// allowedInlineType allows certain MIME types that are considered safe to be used
// for "inline" disposition with Linksharing serving requests on public domains.
func allowedInlineType(contentType string) bool {
	switch contentType {
	case "application/pdf":
	case "image/bmp":
	case "image/jpeg":
	case "image/x-png":
	case "image/png":
	case "image/gif":
	default:
		return false
	}
	return true
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

// predictRange parses a Range header string as per RFC 7233 without
// knowing the size, modtime, or etag and predicts the download offset
// and length to potentially save round trips to the satellite.
func predictRange(s string) (*uplink.DownloadOptions, error) {
	if s == "" {
		return nil, nil // header not present
	}
	const b = "bytes="
	if !strings.HasPrefix(s, b) {
		return nil, errors.New("invalid range")
	}
	for _, ra := range strings.Split(s[len(b):], ",") {
		ra = textproto.TrimString(ra)
		if ra == "" {
			continue
		}
		start, end, ok := strings.Cut(ra, "-")
		if !ok {
			return nil, errors.New("invalid range")
		}
		start, end = textproto.TrimString(start), textproto.TrimString(end)
		var offset, length int64
		if start == "" {
			// If no start is specified, end specifies the
			// range start relative to the end of the file,
			// and we are dealing with <suffix-length>
			// which has to be a non-negative integer as per
			// RFC 7233 Section 2.1 "Byte-Ranges".
			if end == "" || end[0] == '-' {
				return nil, errors.New("invalid range")
			}
			i, err := strconv.ParseInt(end, 10, 64)
			if err != nil || i < 0 {
				return nil, errors.New("invalid range")
			}
			offset = -i
			length = -1
		} else {
			i, err := strconv.ParseInt(start, 10, 64)
			if err != nil || i < 0 {
				return nil, errors.New("invalid range")
			}
			offset = i
			if end == "" {
				// If no end is specified, range extends to end of the file.
				length = -1
			} else {
				i, err := strconv.ParseInt(end, 10, 64)
				if err != nil || offset > i {
					return nil, errors.New("invalid range")
				}
				length = i - offset + 1
			}
		}

		// satellite doesn't currently support multiple ranges
		return &uplink.DownloadOptions{Offset: offset, Length: length}, nil
	}
	return nil, errors.New("range prediction failed")
}

// optionsToRange converts a relative options to an absolute range to
// match what httpranger produces so later calls to Ranger don't end
// in a cache miss.
func optionsToRange(length int64, options *uplink.DownloadOptions) httpranger.HTTPRange {
	var r httpranger.HTTPRange
	switch {
	case options == nil:
		r.Length = length
	case options.Offset < 0:
		r.Start = length + options.Offset
		r.Length = length - options.Offset
	case options.Length < 0:
		r.Start = options.Offset
		r.Length = length - options.Offset
	default:
		r.Start = options.Offset
		r.Length = options.Length
	}
	// libuplink truncates lengths that are too long for us
	if (r.Start < length) && (r.Start+r.Length > length) {
		r.Length = length - r.Start
	}
	return r
}

// isContentCodingAcceptable returns whether the specified content coding is acceptable
// in accordance with RFC 9110 Section 12.5.3.
// It panics if the coding is the wildcard token ("*").
func isContentCodingAcceptable(coding string, header http.Header) bool {
	coding = strings.ToLower(coding)
	if coding == "*" {
		panic("'*' is a reserved content coding token")
	}
	if _, ok := header["Accept-Encoding"]; !ok {
		return true
	}
	codingWeights := parseAcceptEncodingHeader(header)
	if len(codingWeights) == 0 {
		return coding == noContentCoding
	}
	weight, hasCoding := codingWeights[coding]
	if hasCoding {
		if weight == 0 {
			return false
		}
	} else if wildcardWeight, ok := codingWeights["*"]; ok && wildcardWeight == 0 {
		return false
	}
	return true
}

// parseAcceptEncodingHeader parses the Accept-Encoding header value in accordance with RFC 9110 Section 12.5.3.
func parseAcceptEncodingHeader(header http.Header) (codingWeights map[string]float64) {
	codingWeights = make(map[string]float64)
	value := strings.ToLower(spaceReplacer.Replace(header.Get("Accept-Encoding")))
	for _, codingWeight := range strings.Split(value, ",") {
		parts := strings.Split(codingWeight, ";")
		if parts[0] == "" {
			continue
		}
		weight := 1.0
		if len(parts) > 1 && strings.HasPrefix(parts[1], "q=") {
			if q, err := strconv.ParseFloat(parts[1][2:], 64); err == nil {
				weight = math.Min(math.Max(0, q), 1)
			}
		}
		codingWeights[parts[0]] = weight
	}
	return
}
