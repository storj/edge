// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"html/template"
	"io"
	"io/fs"
)

// Templates implements cached or dynamic rendering of templates.
type Templates struct {
	fs      fs.FS
	dynamic bool
	parsed  *template.Template
}

// NewDynamicTemplates creates a templates handler that always reparses the
// templates on every query.
func NewDynamicTemplates(fs fs.FS) (*Templates, error) {
	return &Templates{
		fs:      fs,
		dynamic: true,
	}, nil
}

// NewStaticTemplates creates a templates handler that parses the templates
// on creation and reuses the result.
func NewStaticTemplates(fs fs.FS) (*Templates, error) {
	parsed, err := template.ParseFS(fs, "*")
	if err != nil {
		return nil, err
	}
	return &Templates{
		fs:      fs,
		dynamic: false,
		parsed:  parsed,
	}, nil
}

// ExecuteTemplate executes the named template.
func (templates *Templates) ExecuteTemplate(w io.Writer, templateName string, data any) error {
	if templates.dynamic {
		parsed, err := template.ParseFS(templates.fs, "*")
		if err != nil {
			return err
		}

		return parsed.ExecuteTemplate(w, templateName, data)
	}

	return templates.parsed.ExecuteTemplate(w, templateName, data)
}
