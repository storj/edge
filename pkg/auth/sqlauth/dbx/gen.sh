#!/bin/sh
set -e
dbx golang -p dbx -d pgx sqlauth.dbx .
( printf '%s\n' '//lint:file-ignore U1000,ST1012 generated file'; cat sqlauth.dbx.go ) > sqlauth.dbx.go.tmp && mv sqlauth.dbx.go.tmp sqlauth.dbx.go
gofmt -w sqlauth.dbx.go
