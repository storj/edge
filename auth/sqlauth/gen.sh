#!/bin/sh

set -e

dbx golang -p sqlauth -d pgxcockroach -d sqlite3 sqlauth.dbx .

(
    echo '//lint:file-ignore U1000 generated file'
    echo '//lint:file-ignore ST1012 generated file'
    cat sqlauth.dbx.go
) > sqlauth.dbx.go.tmp

mv sqlauth.dbx.go.tmp sqlauth.dbx.go
