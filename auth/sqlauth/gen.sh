#!/bin/sh

dbx golang -p sqlauth -d pgxcockroach -d sqlite3 sqlauth.dbx .
( echo '//lint:file-ignore * generated file'; cat sqlauth.dbx.go ) > sqlauth.dbx.go.tmp && mv sqlauth.dbx.go.tmp sqlauth.dbx.go
