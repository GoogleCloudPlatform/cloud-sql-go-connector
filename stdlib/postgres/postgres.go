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

package postgres

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"net"

	"cloud.google.com/go/cloudsqlconn"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/stdlib"
)

func init() {
	sql.Register("cloudsql-postgres", &pgDriver{})
}

type pgDriver struct{}

func (*pgDriver) Open(name string) (driver.Conn, error) {
	config, err := pgx.ParseConfig(name)
	if err != nil {
		return nil, err
	}
	h := config.Config.Host          // Extract instance connection name
	config.Config.Host = "localhost" // Replace it with a default value
	config.DialFunc = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return cloudsqlconn.Dial(ctx, h)
	}
	dbURI := stdlib.RegisterConnConfig(config)
	return stdlib.GetDefaultDriver().Open(dbURI)
}
