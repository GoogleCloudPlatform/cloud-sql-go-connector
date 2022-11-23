// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pgxv5_test

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"cloud.google.com/go/cloudsqlconn"
	"cloud.google.com/go/cloudsqlconn/postgres/pgxv5"
)

var (
	// "Cloud SQL Postgres instance connection name, in the form of
	// 'project:region:instance'.
	postgresConnName = os.Getenv("POSTGRES_CONNECTION_NAME")
	// Name of database user.
	postgresUser = os.Getenv("POSTGRES_USER")
	// Password for the database user; be careful when entering a password on
	// the command line (it may go into your terminal's history).
	postgresPass = os.Getenv("POSTGRES_PASS")
	// Name of the database to connect to.
	postgresDB = os.Getenv("POSTGRES_DB")
	// Name of database IAM user.
	postgresUserIAM = os.Getenv("POSTGRES_USER_IAM")
)

func requirePostgresVars(t *testing.T) {
	switch "" {
	case postgresConnName:
		t.Fatal("'POSTGRES_CONNECTION_NAME' env var not set")
	case postgresUser:
		t.Fatal("'POSTGRES_USER' env var not set")
	case postgresPass:
		t.Fatal("'POSTGRES_PASS' env var not set")
	case postgresDB:
		t.Fatal("'POSTGRES_DB' env var not set")
	case postgresUserIAM:
		t.Fatal("'POSTGRES_USER_IAM' env var not set")
	}
}

// Example shows how to register and use a Cloud SQL Postgres dialer.
func ExampleRegisterDriver() {
	// Note that sslmode=disable is required it does not mean that the connection
	// is unencrypted. All connections via the proxy are completely encrypted.
	pgxv5.RegisterDriver("cloudsql-postgres", cloudsqlconn.WithIAMAuthN())
	db, err := sql.Open(
		"cloudsql-postgres",
		"host=project:region:instance user=postgres dbname=postgres password=password sslmode=disable",
	)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	var now time.Time
	if err := db.QueryRow("SELECT NOW()").Scan(&now); err != nil {
		log.Fatal(err)
	}
	log.Println(now)
}

func TestPostgresHook(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Postgres integration tests")
	}
	testConn := func(db *sql.DB) {
		var now time.Time
		if err := db.QueryRow("SELECT NOW()").Scan(&now); err != nil {
			t.Fatalf("QueryRow failed: %v", err)
		}
		t.Log(now)
	}
	tcs := []struct {
		user         string
		password     string
		registerFunc func(name string, opts ...cloudsqlconn.Option) (func() error, error)
		driverName   string
		opts         []cloudsqlconn.Option
	}{
		{
			driverName:   "cloud-sql-postgres-v5",
			user:         postgresUser,
			password:     postgresPass,
			registerFunc: pgxv5.RegisterDriver,
		},
		{
			driverName:   "cloud-sql-postgres-iam-v5",
			user:         postgresUserIAM,
			password:     postgresPass,
			registerFunc: pgxv5.RegisterDriver,
			opts:         []cloudsqlconn.Option{cloudsqlconn.WithIAMAuthN()},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.driverName, func(t *testing.T) {
			cleanup, err := tc.registerFunc(tc.driverName, tc.opts...)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if cErr := cleanup(); cErr != nil {
					t.Logf("%v cleanup: %v", tc.driverName, cErr)
				}
			})
			db, err := sql.Open(
				tc.driverName,
				fmt.Sprintf("host=%s user=%s password=%s dbname=%s sslmode=disable",
					postgresConnName, tc.user, tc.password, postgresDB),
			)
			if err != nil {
				t.Fatalf("sql.Open want err = nil, got = %v", err)
			}
			defer db.Close()
			testConn(db)
		})
	}
}
