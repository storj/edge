// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"context"
	"html/template"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strings"

	"storj.io/common/memory"
	"storj.io/edge/pkg/errdata"
	"storj.io/uplink"
	"storj.io/zipper"
)

type breadcrumb struct {
	Prefix string
	URL    string
}

type listObject struct {
	Key    string
	URL    template.URL
	Size   string
	Prefix bool
}

func (handler *Handler) servePrefix(ctx context.Context, w http.ResponseWriter, project *uplink.Project, pr *parsedRequest, archivePath, cursor string) (err error) {
	defer mon.Task()(&ctx)(&err)
	var input struct {
		Title          string
		Breadcrumbs    []breadcrumb
		Objects        []listObject
		NextCursor     string
		ShowBackButton bool
	}
	input.Title = pr.title
	input.Breadcrumbs = append(input.Breadcrumbs, pr.root)
	if pr.visibleKey != "" {
		parts := strings.Split(strings.TrimRight(pr.visibleKey, "/"), "/")
		for i, prefix := range parts {
			url := input.Breadcrumbs[i].URL + prefix
			if archivePath == "" || i < len(parts)-1 {
				url += "/"
			}
			input.Breadcrumbs = append(input.Breadcrumbs, breadcrumb{Prefix: prefix, URL: url})
		}
	}

	input.Objects = make([]listObject, 0)
	if len(archivePath) > 0 {
		input.Objects, err = listObjectsArchive(ctx, project, pr)
	} else {
		input.Objects, input.NextCursor, err = listObjectsPrefix(ctx, project, pr, cursor, handler.listPageLimit)
	}
	if err != nil {
		return err
	}

	if len(input.Objects) == 0 {
		return errdata.WithAction(uplink.ErrObjectNotFound, "serve prefix - empty")
	}

	if cursor != "" {
		input.ShowBackButton = true
	}

	handler.renderTemplate(w, "prefix-listing.html", pageData{
		Data:             input,
		Title:            pr.title,
		ShowViewContents: len(archivePath) > 0,
	})

	return nil
}

func listObjectsPrefix(ctx context.Context, project *uplink.Project, pr *parsedRequest, cursor string, limit int) (objects []listObject, nextCursor string, err error) {
	projectObjects := project.ListObjects(ctx, pr.bucket, &uplink.ListObjectsOptions{
		Prefix: pr.realKey,
		Cursor: cursor,
		System: true,
	})

	for limit > 0 && projectObjects.Next() {
		item := projectObjects.Item()
		key := item.Key[len(pr.realKey):]
		var keyURL string
		if item.IsPrefix {
			keyURL = url.PathEscape(strings.TrimSuffix(key, "/")) + "/"
		} else {
			keyURL = url.PathEscape(key)
		}
		objects = append(objects, listObject{
			Key:    key,
			URL:    template.URL("./" + keyURL + "?wrap=1"),
			Size:   memory.Size(item.System.ContentLength).Base10String(),
			Prefix: item.IsPrefix,
		})
		limit--
	}
	// run Next one more time to see if there are more objects beyond this page.
	if projectObjects.Next() {
		nextCursor = objects[len(objects)-1].Key
	}
	return objects, nextCursor, errdata.WithAction(projectObjects.Err(), "list objects")
}

func listObjectsArchive(ctx context.Context, project *uplink.Project, pr *parsedRequest) (objects []listObject, err error) {
	zip, err := zipper.OpenPack(ctx, project, pr.bucket, pr.realKey)
	if err != nil {
		return objects, errdata.WithStatus(err, http.StatusInternalServerError)
	}

	zipItems := zip.List()
	sort.Strings(zipItems)
	for _, name := range zipItems {
		keyURL := url.PathEscape(filepath.Base(pr.realKey)) + "?path=" + url.QueryEscape(name)
		f, err := zip.FileInfo(ctx, name)
		if err != nil {
			// err here is only if invalid strings are returned from zip.List()
			return objects, errdata.WithStatus(err, http.StatusInternalServerError)
		}
		objects = append(objects, listObject{
			Key:    name,
			URL:    template.URL("./" + keyURL + "&wrap=1"),
			Size:   memory.Size(f.Size).Base10String(),
			Prefix: false,
		})
	}
	return objects, nil
}
