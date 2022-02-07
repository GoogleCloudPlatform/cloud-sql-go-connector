// Copyright 2022 Google LLC

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !skip_sqlserver
// +build !skip_sqlserver

package cloudsqlconn_test

import (
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"cloud.google.com/go/cloudsqlconn/sqlserver/mssql"
)

var (
	sqlserverConnName = os.Getenv("SQLSERVER_CONNECTION_NAME") // "Cloud SQL SqlServer instance connection name, in the form of 'project:region:instance'.
	sqlserverUser     = os.Getenv("SQLSERVER_USER")            // Name of database user.
	sqlserverPass     = os.Getenv("SQLSERVER_PASS")            // Password for the database user; be careful when entering a password on the command line (it may go into your terminal's history).
	sqlserverDB       = os.Getenv("SQLSERVER_DB")              // Name of the database to connect to.
)

func requireSqlServerVars(t *testing.T) {
	switch "" {
	case sqlserverConnName:
		t.Fatal("'SQLSERVER_CONNECTION_NAME' env var not set")
	case sqlserverUser:
		t.Fatal("'SQLSERVER_USER' env var not set")
	case sqlserverPass:
		t.Fatal("'SQLSERVER_PASS' env var not set")
	case sqlserverDB:
		t.Fatal("'SQLSERVER_DB' env var not set")
	}
}

func TestSqlServerHook(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping SqlServer integration tests")
	}
	testConn := func(db *sql.DB) {
		var now time.Time
		if err := db.QueryRow("SELECT getdate()").Scan(&now); err != nil {
			t.Fatalf("QueryRow failed: %v", err)
		}
		t.Log(now)
	}
	err := mssql.RegisterDriver("cloudsql-sqlserver")
	if err != nil {
		t.Fatalf("failed to register driver: %v", err)
	}
	db, err := sql.Open(
		"cloudsql-sqlserver",
		fmt.Sprintf("sqlserver://%s:%s@localhost?database=%s&cloudsql=%s",
			sqlserverUser, sqlserverPass, sqlserverDB, sqlserverConnName),
	)
	if err != nil {
		t.Fatalf("sql.Open want err = nil, got = %v", err)
	}
	defer db.Close()
	testConn(db)
}
