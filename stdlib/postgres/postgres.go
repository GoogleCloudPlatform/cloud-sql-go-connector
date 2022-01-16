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
