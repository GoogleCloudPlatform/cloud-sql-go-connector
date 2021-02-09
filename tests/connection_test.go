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

package tests

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v4"
	"github.com/kurtisvg/cloud-sql-go-connector/dialer"
)

var (
	postgresConnName = os.Getenv("POSTGRES_CONNECTION_NAME") // "Cloud SQL Postgres instance connection name, in the form of 'project:region:instance'.
	postgresUser     = os.Getenv("POSTGRES_USER")            // Name of database user.
	postgresPass     = os.Getenv("POSTGRES_PASS")            // Password for the database user; be careful when entering a password on the command line (it may go into your terminal's history).
	postgresDb       = os.Getenv("POSTGRES_DB")              // Name of the database to connect to.
)

func TestPgxConnect(t *testing.T) {
	ctx := context.Background()

	dsn := fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable", postgresUser, postgresPass, postgresDb)
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("failed to parse pgx config: %v", err)
	}
	config.DialFunc = func(ctx context.Context, network string, instance string) (net.Conn, error) {
		return dialer.Dial(ctx, postgresConnName)
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
