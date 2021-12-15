// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"context"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"storj.io/common/memory"
	"storj.io/gateway-mt/pkg/errdata"
	"storj.io/uplink"
)

type breadcrumb struct {
	Prefix string
	URL    string
}

func (handler *Handler) servePrefix(ctx context.Context, w http.ResponseWriter, project *uplink.Project, pr *parsedRequest) (err error) {
	defer mon.Task()(&ctx)(&err)

	type Object struct {
		Key    string
		URL    template.URL
		Size   string
		Prefix bool
	}

	var input struct {
		Title       string
		Breadcrumbs []breadcrumb
		Objects     []Object
	}
	input.Title = pr.title
	input.Breadcrumbs = append(input.Breadcrumbs, pr.root)
	if pr.visibleKey != "" {
		trimmed := strings.TrimRight(pr.visibleKey, "/")
		for i, prefix := range strings.Split(trimmed, "/") {
			input.Breadcrumbs = append(input.Breadcrumbs, breadcrumb{
				Prefix: prefix,
				URL:    input.Breadcrumbs[i].URL + prefix + "/",
			})
		}
	}

	input.Objects = make([]Object, 0)

	objects := project.ListObjects(ctx, pr.bucket, &uplink.ListObjectsOptions{
		Prefix: pr.realKey,
		System: true,
	})

	// TODO add paging
	for objects.Next() {
		item := objects.Item()
		key := item.Key[len(pr.realKey):]
		var keyURL string
		if item.IsPrefix {
			keyURL = url.PathEscape(strings.TrimSuffix(key, "/")) + "/"
		} else {
			keyURL = url.PathEscape(key)
		}

		input.Objects = append(input.Objects, Object{
			Key:    key,
			URL:    template.URL(keyURL),
			Size:   memory.Size(item.System.ContentLength).Base10String(),
			Prefix: item.IsPrefix,
		})
	}
	err = objects.Err()
	if err != nil {
		return errdata.WithAction(err, "list objects")
	}

	if len(input.Objects) == 0 {
		return errdata.WithAction(uplink.ErrObjectNotFound, "serve prefix - empty")
	}

	handler.renderTemplate(w, "prefix-listing.html", pageData{
		Data:  input,
		Title: pr.title,
	})
	return nil
}
