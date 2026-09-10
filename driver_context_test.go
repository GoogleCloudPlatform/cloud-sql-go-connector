// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cloudsqlconn_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	"cloud.google.com/go/cloudsqlconn"
	"cloud.google.com/go/cloudsqlconn/internal/mock"
	"cloud.google.com/go/cloudsqlconn/mysql/mysql"
	"cloud.google.com/go/cloudsqlconn/postgres/pgxv4"
	"cloud.google.com/go/cloudsqlconn/postgres/pgxv5"
	"github.com/google/uuid"
)

func TestRegisteredDriverConnectionContext(t *testing.T) {
	for _, drv := range []struct {
		name     string
		register func(string, ...cloudsqlconn.Option) (func() error, error)
	}{
		{"mysql", mysql.RegisterDriver},
		{"pgxv5", pgxv5.RegisterDriver},
		{"pgxv4", pgxv4.RegisterDriver},
	} {
		for _, mode := range []string{"cancel", "deadline"} {
			t.Run(drv.name+"/"+mode, func(t *testing.T) {
				entered, release := make(chan struct{}, 1), make(chan struct{})
				transport := driverContextTransport(func(r *http.Request) (*http.Response, error) {
					select {
					case entered <- struct{}{}:
					default:
					}
					select {
					case <-release:
						return nil, context.Canceled
					case <-r.Context().Done():
						return nil, r.Context().Err()
					}
				})
				name := "cloudsql-context-" + uuid.NewString()
				cleanup, err := drv.register(name,
					cloudsqlconn.WithTokenSource(mock.EmptyTokenSource{}),
					cloudsqlconn.WithHTTPClient(&http.Client{Transport: transport}),
				)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					close(release)
					if err := cleanup(); err != nil {
						t.Error(err)
					}
				})
				dsn := "host=test-project:us-central1:test-instance user=test dbname=test sslmode=disable"
				if drv.name == "mysql" {
					dsn = fmt.Sprintf("test@%s(test-project:us-central1:test-instance)/test", name)
				}
				db, err := sql.Open(name, dsn)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := db.Close(); err != nil {
						t.Error(err)
					}
				})
				db.SetMaxOpenConns(1)

				ctx, cancel := context.WithCancel(context.Background())
				wantErr := context.Canceled
				if mode == "deadline" {
					cancel()
					ctx, cancel = context.WithTimeout(context.Background(), time.Second)
					wantErr = context.DeadlineExceeded
				}
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- db.PingContext(ctx) }()
				select {
				case <-entered:
				case err := <-done:
					t.Fatalf("connection returned before reaching the API: %v", err)
				case <-time.After(5 * time.Second):
					t.Fatal("connection did not reach the test API transport")
				}
				if mode == "cancel" {
					cancel()
				}
				// The API remains blocked. The caller's context must release the slot.
				select {
				case err := <-done:
					if !errors.Is(err, wantErr) {
						t.Fatalf("PingContext error = %v, want %v", err, wantErr)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("connection ignored the caller's context")
				}
				if stats := db.Stats(); stats.OpenConnections != 0 || stats.InUse != 0 {
					t.Fatalf("connection attempt retained a pool slot: %+v", stats)
				}

				driverCtx, ok := db.Driver().(driver.DriverContext)
				if !ok {
					t.Fatal("DB.Driver does not implement driver.DriverContext")
				}
				wantPackage := "cloud.google.com/go/cloudsqlconn/postgres/pgxv5"
				if drv.name == "mysql" {
					wantPackage = "cloud.google.com/go/cloudsqlconn/mysql/mysql"
				}
				if got := reflect.TypeOf(db.Driver()).Elem().PkgPath(); got != wantPackage {
					t.Fatalf("DB.Driver package = %q, want %q", got, wantPackage)
				}
				connector, err := driverCtx.OpenConnector(dsn)
				if err != nil {
					t.Fatal(err)
				}
				if connector.Driver() != db.Driver() {
					t.Fatal("connector did not preserve the registered driver")
				}
				if _, err := driverCtx.OpenConnector("invalid"); err == nil {
					t.Fatal("OpenConnector accepted an invalid DSN")
				}
			})
		}
	}
}

type driverContextTransport func(*http.Request) (*http.Response, error)

func (f driverContextTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
