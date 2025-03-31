// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/zeebo/errs"

	"storj.io/common/grant"
	"storj.io/common/memory"
	"storj.io/common/paths"
	"storj.io/common/sync2"
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
		Title            string
		Breadcrumbs      []breadcrumb
		Objects          []listObject
		NextCursor       string
		ShowBackButton   bool
		IsParentListable bool
	}
	input.Title = pr.title
	input.Breadcrumbs = append(input.Breadcrumbs, pr.root)
	if pr.visibleKey != "" {
		trimmed := strings.TrimRight(pr.visibleKey, "/")
		parts := strings.Split(trimmed, "/")
		for i, prefix := range parts {
			url := input.Breadcrumbs[i].URL + prefix
			if archivePath == "" || i < len(parts)-1 {
				url += "/"
			}
			input.Breadcrumbs = append(input.Breadcrumbs, breadcrumb{Prefix: prefix, URL: url})
		}

		serializedAccess, err := pr.access.Serialize()
		if err != nil {
			return errdata.WithAction(err, "serve prefix")
		}
		access, err := grant.ParseAccess(serializedAccess)
		if err != nil {
			return errdata.WithAction(err, "serve prefix")
		}

		var parent string
		if index := strings.LastIndexByte(trimmed, '/'); index != -1 {
			parent = pr.visibleKey[:index]
		}
		if _, _, base := access.EncAccess.Store.LookupUnencrypted(pr.bucket, paths.NewUnencrypted(parent)); base != nil {
			input.IsParentListable = true
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
		AllowDownload:    handler.isDownloadAllowed(pr.access),
		ArchivePath:      archivePath,
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
		if key == FilePlaceholder {
			continue
		}
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

		// if next object is file placeholder, check if it's the final object. If so, don't
		// set nextCursor, so we don't show a Next button which leads to an empty page.
		if projectObjects.Item().Key[len(pr.realKey):] == FilePlaceholder {
			if !projectObjects.Next() {
				nextCursor = ""
			}
		}
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

func (handler *Handler) downloadPrefix(ctx context.Context, w http.ResponseWriter, project *uplink.Project, pr *parsedRequest, downloadKind string) (err error) {
	defer mon.Task()(&ctx)(&err)

	if downloadKind != "zip" && downloadKind != "tar.gz" {
		return errdata.WithStatus(errs.New("Invalid download kind provided. Must be 'zip' or 'tar.gz'"), http.StatusBadRequest)
	}

	if downloadKind == "zip" {
		return handler.downloadZip(ctx, w, project, pr)
	}
	return handler.downloadTarGz(ctx, w, project, pr)
}

func (handler *Handler) downloadZip(ctx context.Context, w http.ResponseWriter, project *uplink.Project, pr *parsedRequest) (err error) {
	defer mon.Task()(&ctx)(&err)

	fileName := pr.bucket
	endOfPrefix := path.Base(pr.realKey)
	if endOfPrefix != "." && endOfPrefix != "/" {
		fileName = endOfPrefix
	}
	fileName += ".zip"
	w.Header().Set("Content-Disposition", "attachment; filename="+fileName)

	zipWriter := zip.NewWriter(w)
	defer func() { err = errs.Combine(err, zipWriter.Close()) }()

	objects := project.ListObjects(ctx, pr.bucket, &uplink.ListObjectsOptions{
		Prefix:    pr.realKey,
		Recursive: true,
		System:    true,
	})

	totalCount := 0
	zipLimitExceeded := errs.New("zip limit exceeded")
	processItem := func(item *uplink.Object) (err error) {
		totalCount++
		// this check is necessary to limit the amount of memory that can be consumed due to downloading zip files containing many objects
		// zip file headers must be kept in memory until the file is closed
		if totalCount > handler.downloadZipLimit {
			header := zip.FileHeader{
				Name:     "TRUNCATED.txt",
				Method:   zip.Deflate,
				Modified: time.Now(),
			}

			zipEntry, err := zipWriter.CreateHeader(&header)
			if err != nil {
				return err
			}
			fileMessage := fmt.Sprintf(`This archive contains only the first %d objects from the downloaded prefix.
To download a larger number of objects at once, download the prefix using the tar.gz archive.`, handler.downloadZipLimit)
			_, err = sync2.Copy(ctx, zipEntry, bytes.NewReader([]byte(fileMessage)))
			if err != nil {
				return err
			}
			return zipLimitExceeded
		}

		object, err := project.DownloadObject(ctx, pr.bucket, item.Key, nil)
		if err != nil {
			return err
		}
		defer func() { err = errs.Combine(err, object.Close()) }()

		header := zip.FileHeader{
			Name:     item.Key[len(pr.realKey):],
			Method:   zip.Deflate,
			Modified: item.System.Created,
		}

		zipEntry, err := zipWriter.CreateHeader(&header)
		if err != nil {
			return err
		}
		_, err = sync2.Copy(ctx, zipEntry, object)
		if err != nil {
			return err
		}
		return nil
	}

	for objects.Next() {
		if err := processItem(objects.Item()); err != nil {
			if errors.Is(err, zipLimitExceeded) {
				return nil
			}
			return err
		}
	}
	if err := objects.Err(); err != nil {
		return err
	}

	return nil
}

func (handler *Handler) downloadTarGz(ctx context.Context, w http.ResponseWriter, project *uplink.Project, pr *parsedRequest) (err error) {
	defer mon.Task()(&ctx)(&err)

	fileName := pr.bucket
	endOfPrefix := path.Base(pr.realKey)
	if endOfPrefix != "." && endOfPrefix != "/" {
		fileName = endOfPrefix
	}
	fileName += ".tar.gz"
	w.Header().Set("Content-Disposition", "attachment; filename="+fileName)

	gzipWriter := gzip.NewWriter(w)
	defer func() { err = errs.Combine(err, gzipWriter.Close()) }()
	tarWriter := tar.NewWriter(gzipWriter)
	defer func() { err = errs.Combine(err, tarWriter.Close()) }()

	objects := project.ListObjects(ctx, pr.bucket, &uplink.ListObjectsOptions{
		Prefix:    pr.realKey,
		Recursive: true,
		System:    true,
	})

	processItem := func(item *uplink.Object) (err error) {
		object, err := project.DownloadObject(ctx, pr.bucket, item.Key, nil)
		if err != nil {
			return err
		}
		defer func() { err = errs.Combine(err, object.Close()) }()
		header := tar.Header{
			Name:    item.Key[len(pr.realKey):],
			ModTime: item.System.Created,
			Size:    item.System.ContentLength,
			Mode:    0600,
		}
		err = tarWriter.WriteHeader(&header)
		if err != nil {
			return err
		}
		_, err = sync2.Copy(ctx, tarWriter, object)
		if err != nil {
			return err
		}
		return nil
	}

	for objects.Next() {
		if err := processItem(objects.Item()); err != nil {
			return err
		}
	}
	if err := objects.Err(); err != nil {
		return err
	}

	return nil
}
