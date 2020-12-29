#!/bin/sh

set -e

dbx golang -p sqlauth -d pgxcockroach -d sqlite3 sqlauth.dbx .
( printf '%s\n' '//lint:file-ignore U1000,ST1012 generated file'; cat sqlauth.dbx.go ) > sqlauth.dbx.go.tmp && mv sqlauth.dbx.go.tmp sqlauth.dbx.go
gofmt -r "*sql.Tx -> tagsql.Tx" -w sqlauth.dbx.go
gofmt -r "*sql.Rows -> tagsql.Rows" -w sqlauth.dbx.go
perl -0777 -pi \
  -e 's,\t"math/rand"\n\),\t"math/rand"\n\n\t"storj.io/private/tagsql"\n\),' \
  sqlauth.dbx.go
perl -0777 -pi \
  -e 's/type DB struct \{\n\t\*sql\.DB/type DB struct \{\n\ttagsql.DB/' \
  sqlauth.dbx.go
perl -0777 -pi \
  -e 's/\tdb = &DB\{\n\t\tDB: sql_db,/\tdb = &DB\{\n\t\tDB: tagsql.Wrap\(sql_db\),/' \
  sqlauth.dbx.go