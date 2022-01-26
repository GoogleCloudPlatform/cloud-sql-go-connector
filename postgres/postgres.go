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

// RegisterDriver registers a Postgres driver that uses the cloudsqlconn.Dialer
// configured with the provided options. The choice of name is entirely up to
// the caller and may be used to distinguish between multiple registrations of
// differently configured Dialers.
// Note: The underlying driver uses the latest version of pgx.
func RegisterDriver(name string, opts []cloudsqlconn.DialerOption, dopts ...cloudsqlconn.DialOption) {
	sql.Register(name, &pgDriver{
		opts:     opts,
		dialOpts: dopts,
	})
}

type dialerConn struct {
	driver.Conn
	dialer *cloudsqlconn.Dialer
}

func (c *dialerConn) Close() error {
	c.dialer.Close()
	return c.Conn.Close()
}

type pgDriver struct {
	opts     []cloudsqlconn.DialerOption
	dialOpts []cloudsqlconn.DialOption
}

// Open accepts a keyword/value formatted connection string and returns a
// connection to the database using cloudsqlconn.Dialer. The Cloud SQL instance
// connection name should be specified in the host field. For example:
//
// "host=my-project:us-central1:my-db-instance user=myuser password=mypass"
func (p *pgDriver) Open(name string) (driver.Conn, error) {
	config, err := pgx.ParseConfig(name)
	if err != nil {
		return nil, err
	}
	instConnName := config.Config.Host // Extract instance connection name
	config.Config.Host = "localhost"   // Replace it with a default value
	d, err := cloudsqlconn.NewDialer(context.Background(), p.opts...)
	if err != nil {
		return nil, err
	}
	config.DialFunc = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return d.Dial(ctx, instConnName, p.dialOpts...)
	}
	dbURI := stdlib.RegisterConnConfig(config)
	conn, err := stdlib.GetDefaultDriver().Open(dbURI)
	if err != nil {
		return nil, err
	}
	return &dialerConn{Conn: conn, dialer: d}, nil
}
