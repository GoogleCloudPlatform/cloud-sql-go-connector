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

package cloudsqlconn_test

import (
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"cloud.google.com/go/cloudsqlconn"
	"cloud.google.com/go/cloudsqlconn/mysql/mysql"
)

var (
	mysqlConnName = os.Getenv("MYSQL_CONNECTION_NAME") // "Cloud SQL MySQL instance connection name, in the form of 'project:region:instance'.
	mysqlUser     = os.Getenv("MYSQL_USER")            // Name of database user.
	mysqlIAMUser  = os.Getenv("MYSQL_USER_IAM")        // Name of database IAM user.
	mysqlPass     = os.Getenv("MYSQL_PASS")            // Password for the database user; be careful when entering a password on the command line (it may go into your terminal's history).
	mysqlDB       = os.Getenv("MYSQL_DB")              // Name of the database to connect to.
)

func requireMySQLVars(t *testing.T) {
	switch "" {
	case mysqlConnName:
		t.Fatal("'MYSQL_CONNECTION_NAME' env var not set")
	case mysqlUser:
		t.Fatal("'MYSQL_USER' env var not set")
	case mysqlPass:
		t.Fatal("'MYSQL_PASS' env var not set")
	case mysqlDB:
		t.Fatal("'MYSQL_DB' env var not set")
	}
}

func TestMySQLDriver(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping MySQL integration tests")
	}
	testConn := func(db *sql.DB) {
		var now time.Time
		if err := db.QueryRow("SELECT NOW()").Scan(&now); err != nil {
			t.Fatalf("QueryRow failed: %v", err)
		}
		t.Log(now)
	}
	cleanup, err := mysql.RegisterDriver("cloudsql-mysql")
	if err != nil {
		t.Fatalf("failed to register driver: %v", err)
	}
	defer cleanup()
	db, err := sql.Open(
		"mysql",
		fmt.Sprintf("%s:%s@cloudsql-mysql(%s)/%s?parseTime=true",
			mysqlUser, mysqlPass, mysqlConnName, mysqlDB),
	)
	if err != nil {
		t.Fatalf("sql.Open want err = nil, got = %v", err)
	}
	defer db.Close()
	testConn(db)
}

func TestMySQLDriverIAMAuthN(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping MySQL integration tests")
	}
	testConn := func(db *sql.DB) {
		var now time.Time
		if err := db.QueryRow("SELECT NOW()").Scan(&now); err != nil {
			t.Fatalf("QueryRow failed: %v", err)
		}
		t.Log(now)
	}
	cleanup, err := mysql.RegisterDriver("cloudsql-mysql", cloudsqlconn.WithIAMAuthN())
	if err != nil {
		t.Fatalf("failed to register driver: %v", err)
	}
	defer cleanup()
	db, err := sql.Open(
		"mysql",
		fmt.Sprintf("%s:empty@cloudsql-mysql(%s)/%s?parseTime=true",
			mysqlIAMUser, mysqlConnName, mysqlDB),
	)
	if err != nil {
		t.Fatalf("sql.Open want err = nil, got = %v", err)
	}
	defer db.Close()
	testConn(db)
}
