// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package httpauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestShift(t *testing.T) {
	cases := []struct {
		In  string
		Dir string
		Rem string
	}{
		{"/foo/bar", "/foo", "/bar"},
		{"/foo", "/foo", ""},
		{"/", "/", ""},
		{"//", "/", "/"},
		{"//bar", "/", "/bar"},
		{"", "", ""},
		{"foo/bar", "foo/", "bar"},
		{"bar", "bar", ""},
	}

	for _, tc := range cases {
		dir, rem := shift(tc.In)
		require.Equal(t, tc.Dir, dir)
		require.Equal(t, tc.Rem, rem)
	}
}

func TestTrim(t *testing.T) {
	cases := []struct {
		In  string
		Out string
	}{
		{"/foo/bar", "foo/bar"},
		{"/foo", "foo"},
		{"/", ""},
		{"//", "/"},
		{"//bar", "/bar"},
		{"", ""},
		{"foo/bar", "foo/bar"},
		{"bar", "bar"},
	}

	for _, tc := range cases {
		require.Equal(t, tc.Out, trim(tc.In))
	}
}

func TestDir(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {})
	matches := func(path string, dir Dir) bool {
		rec := httptest.NewRecorder()
		dir.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec.Code == http.StatusOK
	}

	// matches on basic functionality
	require.True(t, matches("/foo/bar", Dir{"/foo": Dir{"/bar": ok}}))
	require.False(t, matches("/bar/foo", Dir{"/foo": Dir{"/bar": ok}}))

	// can use "" to assert path ends
	require.True(t, matches("/foo/bar", Dir{"/foo": Dir{"/bar": Dir{"": ok}}}))
	require.False(t, matches("/foo/bar/baz", Dir{"/foo": Dir{"/bar": Dir{"": ok}}}))
	require.False(t, matches("/foo/bar/", Dir{"/foo": Dir{"/bar": Dir{"": ok}}}))

	// * is a wildcard match
	require.True(t, matches("/foo/bar", Dir{"/foo": Dir{"*": ok}}))
	require.True(t, matches("/foo/baz", Dir{"/foo": Dir{"*": ok}}))
	require.True(t, matches("/foo", Dir{"/foo": Dir{"*": ok}}))
	require.False(t, matches("/foobar", Dir{"/foo": Dir{"*": ok}}))

	// * does not consume a component
	require.True(t, matches("/foo/baz", Dir{"/foo": Dir{"*": Dir{"/baz": ok}}}))
	require.False(t, matches("/foo/bif", Dir{"/foo": Dir{"*": Dir{"/baz": ok}}}))

	// empty components can be matched
	require.True(t, matches("/foo//baz", Dir{"/foo": Dir{"/": Dir{"/baz": ok}}}))

	// empty key only matches empty url
	require.False(t, matches("/", Dir{"": ok}))
}

func TestMethod(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {})
	matches := func(method string, m Method) bool {
		rec := httptest.NewRecorder()
		m.ServeHTTP(rec, httptest.NewRequest(method, "/", nil))
		return rec.Code == http.StatusOK
	}

	// matches on basic functionality
	require.True(t, matches("POST", Method{"POST": ok}))
	require.False(t, matches("PUT", Method{"POST": ok}))
}

func TestArg(t *testing.T) {
	arg := new(Arg)
	arg2 := new(Arg)

	// check that argument shifts and captures the path component
	arg.Capture(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		require.Equal(t, "foo", arg.Value(req.Context()))
		require.Equal(t, "/bar", req.URL.Path)
	})).ServeHTTP(nil, httptest.NewRequest("", "/foo/bar", nil))

	// check that empty argument works
	Dir{"/foo": arg.Capture(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		require.Equal(t, "", arg.Value(req.Context()))
		require.Equal(t, "/bar", req.URL.Path)
	}))}.ServeHTTP(nil, httptest.NewRequest("", "/foo//bar", nil))

	// check that no argument is a 404
	rec := httptest.NewRecorder()
	Dir{"/foo": arg.Capture(nil)}.ServeHTTP(rec, httptest.NewRequest("", "/foo", nil))
	require.Equal(t, http.StatusNotFound, rec.Code)

	// check double arguments don't get confused
	arg.Capture(arg2.Capture(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		require.Equal(t, "foo", arg.Value(req.Context()))
		require.Equal(t, "bar", arg2.Value(req.Context()))
		require.Equal(t, "", req.URL.Path)
	}))).ServeHTTP(nil, httptest.NewRequest("", "/foo/bar", nil))
}
