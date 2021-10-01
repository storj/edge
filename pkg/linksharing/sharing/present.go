// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"context"
	"errors"
	"mime"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/memory"
	"storj.io/common/ranger/httpranger"
	"storj.io/gateway-mt/pkg/linksharing/objectranger"
	"storj.io/uplink"
)

type parsedRequest struct {
	access          *uplink.Access
	bucket          string
	realKey         string
	visibleKey      string
	title           string
	root            breadcrumb
	wrapDefault     bool
	downloadDefault bool
	standard        bool
}

func (handler *Handler) present(ctx context.Context, w http.ResponseWriter, r *http.Request, pr *parsedRequest) (err error) {
	defer mon.Task()(&ctx)(&err)

	project, err := handler.uplink.OpenProject(ctx, pr.access)
	if err != nil {
		return WithStatus(WithAction(err, "open project"), http.StatusBadRequest)
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
			return WithAction(err, "stat object")
		}
		if !strings.HasSuffix(pr.realKey, "/") {
			objNotFoundErr := WithAction(err, "stat object")

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
		return WithAction(err, "stat object - index.html")
	}

	// special case for if the user requested a bucket but there's no trailing slash
	if !strings.HasSuffix(r.URL.Path, "/") {
		http.Redirect(w, r, r.URL.Path+"/", http.StatusSeeOther)
		return nil
	}

	return handler.servePrefix(ctx, w, project, pr)
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
	wrap := queryFlagLookup(q, "wrap",
		!queryFlagLookup(q, "view", !pr.wrapDefault))

	if download || (handler.standardOnlyDownloads && pr.standard) {
		w.Header().Set("Content-Disposition", "attachment")
	}
	if (download || !wrap) && !mapOnly {
		contentType := o.Custom["Content-Type"]
		if contentType == "" {
			contentType = mime.TypeByExtension(filepath.Ext(o.Key))
		}
		if contentType != "" {
			if handler.htmlToPlainForStandard && pr.standard && strings.Contains(strings.ToLower(contentType), "html") {
				contentType = "text/plain"
			}
			w.Header().Set("Content-Type", contentType)
		} else {
			w.Header().Set("Content-Type", "application/octet-stream")
		}

		httpranger.ServeContent(ctx, w, r, o.Key, o.System.Created, objectranger.New(project, o, pr.bucket))
		return nil
	}

	locations, pieces, err := handler.getLocations(ctx, pr)
	if err != nil {
		return WithAction(err, "get locations")
	}

	if mapOnly {
		return handler.serveMap(ctx, w, locations, pieces, o, q)
	}
	var input struct {
		Key        string
		Size       string
		NodesCount int
	}
	input.Key = filepath.Base(o.Key)
	input.Size = memory.Size(o.System.ContentLength).Base10String()
	input.NodesCount = len(locations)

	handler.renderTemplate(w, "single-object.html", pageData{
		Data:  input,
		Title: input.Key,
	})
	return nil
}

func (handler *Handler) isPrefix(ctx context.Context, project *uplink.Project, pr *parsedRequest) (bool, error) {
	// we might not having listing permission. if this is the case,
	// guess that we're looking for an index.html and look for that.
	_, err := project.StatObject(ctx, pr.bucket, pr.realKey+"/index.html")
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, uplink.ErrObjectNotFound) {
		return false, WithAction(err, "prefix determination stat")
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
		return false, WithAction(err, "prefix determination list")
	}
	return isPrefix, nil
}
