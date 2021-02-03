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
	"github.com/kurtisvg/cloud-sql-go-connector/pkg/dialer"
)

var (
	instConnName = os.Getenv("INSTANCE_CONNECTION_NAME")
)

func TestConnect(t *testing.T) {
	ctx := context.Background()

	dsn := fmt.Sprintf("host=127.0.0.1 user=%s password=%s dbname=%s sslmode=disable", "my-user", "my-password", "my_db")
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("failed to parse pgx config: %s", err)
	}
	config.DialFunc = func(ctx context.Context, network string, instance string) (net.Conn, error) {
		return dialer.Dial(ctx, instConnName)
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
