// Copyright 2020 Google LLC

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !skip_postgres
// +build !skip_postgres

// Package tests contains end to end tests for verifying compatibility of examples with external resources.
package cloudsqlconn_test

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/cloudsqlconn"
	"github.com/jackc/pgx/v4"

	"cloud.google.com/go/cloudsqlconn/postgres/pgxv4"
)

var (
	postgresConnName = os.Getenv("POSTGRES_CONNECTION_NAME") // "Cloud SQL Postgres instance connection name, in the form of 'project:region:instance'.
	postgresUser     = os.Getenv("POSTGRES_USER")            // Name of database user.
	postgresPass     = os.Getenv("POSTGRES_PASS")            // Password for the database user; be careful when entering a password on the command line (it may go into your terminal's history).
	postgresDb       = os.Getenv("POSTGRES_DB")              // Name of the database to connect to.
	postgresUserIAM  = os.Getenv("POSTGRES_USER_IAM")        // Name of database IAM user.
)

func requirePostgresVars(t *testing.T) {
	switch "" {
	case postgresConnName:
		t.Fatal("'POSTGRES_CONNECTION_NAME' env var not set")
	case postgresUser:
		t.Fatal("'POSTGRES_USER' env var not set")
	case postgresPass:
		t.Fatal("'POSTGRES_PASS' env var not set")
	case postgresDb:
		t.Fatal("'POSTGRES_DB' env var not set")
	case postgresUserIAM:
		t.Fatal("'POSTGRES_USER_IAM' env var not set")
	}
}

func TestPgxConnect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Postgres integration tests")
	}
	requirePostgresVars(t)

	ctx := context.Background()

	dsn := fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable", postgresUser, postgresPass, postgresDb)
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("failed to parse pgx config: %v", err)
	}
	config.DialFunc = func(ctx context.Context, network string, instance string) (net.Conn, error) {
		return cloudsqlconn.Dial(ctx, postgresConnName)
	}

	conn, connErr := pgx.ConnectConfig(ctx, config)
	if connErr != nil {
		t.Fatalf("failed to connect: %s", connErr)
	}
	defer conn.Close(ctx)

	var now time.Time
	err = conn.QueryRow(context.Background(), "SELECT NOW()").Scan(&now)
	if err != nil {
		t.Fatalf("QueryRow failed: %s", err)
	}
	t.Log(now)
}

func TestConnectWithIAMUser(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Postgres integration tests")
	}
	requirePostgresVars(t)

	ctx := context.Background()

	// password is intentionally blank
	dsn := fmt.Sprintf("user=%s password=\"\" dbname=%s sslmode=disable", postgresUserIAM, postgresDb)
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("failed to parse pgx config: %v", err)
	}
	d, err := cloudsqlconn.NewDialer(ctx, cloudsqlconn.WithIAMAuthN())
	if err != nil {
		t.Fatalf("failed to initiate Dialer: %v", err)
	}
	defer d.Close()
	config.DialFunc = func(ctx context.Context, network string, instance string) (net.Conn, error) {
		return d.Dial(ctx, postgresConnName)
	}

	conn, connErr := pgx.ConnectConfig(ctx, config)
	if connErr != nil {
		t.Fatalf("failed to connect: %s", connErr)
	}
	defer conn.Close(ctx)

	var now time.Time
	err = conn.QueryRow(context.Background(), "SELECT NOW()").Scan(&now)
	if err != nil {
		t.Fatalf("QueryRow failed: %s", err)
	}
	t.Log(now)
}

func TestEngineVersion(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Postgres integration tests")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, err := cloudsqlconn.NewDialer(context.Background())
	if err != nil {
		t.Fatalf("failed to init Dialer: %v", err)
	}
	gotEV, err := d.EngineVersion(ctx, postgresConnName)
	if err != nil {
		t.Fatalf("failed to retrieve engine version: %v", err)
	}
	if !strings.Contains(gotEV, "POSTGRES") {
		t.Errorf("InstanceEngineVersion(%s) failed: want 'POSTGRES', got %v", gotEV, err)
	}
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
	pgxv4.RegisterDriver("cloudsql-postgres")
	db, err := sql.Open(
		"cloudsql-postgres",
		fmt.Sprintf("host=%s user=%s password=%s dbname=%s sslmode=disable",
			postgresConnName, postgresUser, postgresPass, postgresDb),
	)
	if err != nil {
		t.Fatalf("sql.Open want err = nil, got = %v", err)
	}
	defer db.Close()
	testConn(db)

	pgxv4.RegisterDriver("cloudsql-postgres-iam", cloudsqlconn.WithIAMAuthN())
	db2, err := sql.Open(
		"cloudsql-postgres-iam",
		fmt.Sprintf("host=%s user=%s dbname=%s sslmode=disable",
			postgresConnName, postgresUserIAM, postgresDb),
	)
	if err != nil {
		t.Fatalf("sql.Open want err = nil, got = %v", err)
	}
	defer db2.Close()
	testConn(db2)
}
