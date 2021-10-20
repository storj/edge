// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package testdata

import (
	"storj.io/private/dbutil/dbschema"
)

// States is the global variable that stores all the states for testing.
// The SQL here represent the final schemas after each step is performed.
var States = []*DBState{
	v0,
}

// DBState allows you to define the desired state of the DB using SQL commands.
// Both the SQL and NewData fields contains SQL that will be executed to create
// the expected DB. The NewData SQL additionally will be executed on the testDB
// to ensure data is consistent.
type DBState struct {
	Version int
	SQL     string
	NewData string
}

// DBSnapshot is a snapshot of a single DB.
type DBSnapshot struct {
	Version int
	Schema  *dbschema.Schema
	Data    *dbschema.Data
}
