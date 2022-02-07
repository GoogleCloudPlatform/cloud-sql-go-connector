# cloud-sql-go-connector
*Warning*: This project is experimental, and is not an officially supported
Google product.

The _Cloud SQL Go Connector_ provides strong encryption and IAM authorization
to an application's connections to a Cloud SQL instance. It provides connection
level authorization only; it _does not_ provide a network path to an instance
that doesn't already exist (i.e. you will still be unable to connect to an
instance's Private IP without access to the correct VPC). For more information
see [About the Cloud SQL Auth proxy][about-proxy].

[about-proxy]: https://cloud.google.com/sql/docs/mysql/sql-proxy

The _Cloud SQL Go Connector_ is an experimental new version of the
[Cloud SQL proxy dialer](dialer.go). Its API is considered unstable and may change
in the future. Please use at your own risk.

[proxy-dialer]: https://github.com/GoogleCloudPlatform/cloudsql-proxy/tree/main/proxy#cloud-sql-proxy-dialer-for-go

## Installation

You can install this repo with `go get`:
```sh
go get cloud.google.com/go/cloudsqlconn
```

## Usage

This package provides several functions for authorizing and encrypting
connections. These functions can be used with your database driver to connect to
your Cloud SQL instance.

The instance connection name for your Cloud SQL instance is always in the
format "project:region:instance".

### Credentials

This repo uses the [Application Default Credentials (ADC)][adc] strategy for
typing providing credentials. Please see the
[golang.org/x/oauth2/google][google-auth] documentation for more information in
how these credentials are sourced.

To explicitly set a specific source for the Credentials to use, see [Using
Option](#using-options) below.

[adc]: https://cloud.google.com/docs/authentication
[google-auth]: https://pkg.go.dev/golang.org/x/oauth2/google#hdr-Credentials

### Using the default Dialer

If you don't need to customize your Dialer's behavior, it is convenient to use
the package's "Dial" option, which initializes a default dialer for you.

#### pgx for Postgres

To use the dialer with [pgx](https://github.com/jackc/pgx), configure the
[pgConn.DialFunc field][pgconn-cfg] to create connections:

```go
// Configure the driver to connect to the database
dsn := fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable", pgUser, pgPass, pgDB)
config, err := pgx.ParseConfig(dsn)
if err != nil {
    log.Fatalf("failed to parse pgx config: %v", err)
}

// Tell the driver to use the Cloud SQL Go Connector to create connections
config.DialFunc = func(ctx context.Context, network string, instance string) (net.Conn, error) {
    return cloudsqlconn.Dial(ctx, "project:region:instance")
}

// Interact with the driver directly as you normally would
conn, connErr := pgx.ConnectConfig(ctx, config)
if connErr != nil {
    log.Fatalf("failed to connect: %s", connErr)
}
defer conn.Close(ctx)
```

[pgconn-cfg]: https://pkg.go.dev/github.com/jackc/pgconn#Config

#### go-sql-driver/mysql for MySQL

The [Go MySQL driver][mysql] does not provide a stand-alone interface for
interacting with a database and instead uses `database/sql`. See [the section
below](#MySQL) on how to use the `database/sql` package with a Cloud SQL MySQL
instance.

[mysql]: https://github.com/go-sql-driver/mysql

### Using Options

If you need to customize something about the `Dialer`, you can initialize
directly with `NewDialer`:

```go
myDialer, err := cloudsqlconn.NewDialer(
    ctx,
    cloudsqlconn.WithCredentialsFile("key.json"),
)
if err != nil {
    log.Fatalf("unable to initialize dialer: %s", err)
}

conn, err := myDialer.Dial(ctx, "project:region:instance")
```

For a full list of customizable behavior, see Option.

### Using DialOptions

If you want to customize things about how the connection is created, use
`Option`:
```go
conn, err := myDialer.Dial(
    ctx,
    "project:region:instance",
    cloudsqlconn.WithPrivateIP(),
)
```

You can also use the `WithDefaultDialOptions` Option to specify
DialOptions to be used by default:
```go
myDialer, err := cloudsqlconn.NewDialer(
    ctx,
    cloudsqlconn.WithDefaultDialOptions(
        cloudsqlconn.WithPrivateIP(),
    ),
)
```

### Using the dialer with database/sql

Using the dialer directly will expose more configuration options. However, it is
possible to use the dialer with the `database/sql` package.

#### Postgres

To use `database/sql`, use `postgres.RegisterDriver` with any necessary Dialer
configuration. Note: the connection string must use the keyword/value format
with host set to the instance connection name.

``` go
package foo

import (
    "database/sql"

    "cloud.google.com/go/cloudsqlconn"
    "cloud.google.com/go/cloudsqlconn/postgres/pgxv4"
)

func Connect() {
    // Without any options:
    pgxv4.RegisterDriver("cloudsql-postgres")

    // Or, with options:
    // pgxv4.RegisterDriver("cloudsql-postgres", cloudsqlconn.WithIAMAuthN())

    db, err := sql.Open(
        "cloudsql-postgres",
        "host=project:region:instance user=myuser password=mypass dbname=mydb sslmode=disable"
	)
    // ... etc
}
```

#### MySQL

To use the dialer with [go-sql-driver/mysql][go-sql-driver], configure a custom
dial function with [mysql.RegisterDialContext][]:

```go
package foo

import (
    "database/sql"

    "cloud.google.com/go/cloudsqlconn"
    "cloud.google.com/go/cloudsqlconn/mysql/mysql"
)

func Connect() {
    // Without any options:
    cleanup, err := mysql.RegisterDriver("cloudsql-mysql", cloudsqlconn.WithCredentialsFile("key.json"))
    if err != nil {
        // ... handle error
    }
    defer cleanup()

    db, err := sql.Open(
        "cloudsql-mysql",
        "host=project:region:instance user=myuser password=mypass dbname=mydb sslmode=disable"
	)
    // ... etc
}
```

[go-sql-driver]: https://github.com/go-sql-driver/mysql
[mysql.RegisterDialContext]: https://pkg.go.dev/github.com/go-sql-driver/mysql#RegisterDialContext


### Enabling Metrics and Tracing

This library includes support for metrics and tracing using [OpenCensus][].
To enable metrics or tracing, you need to configure an [exporter][].
OpenCensus supports many backends for exporters.

For example, to use [Cloud Monitoring][] and [Cloud Trace][], you would
configure an exporter like so:

``` golang
package main

import (
    "contrib.go.opencensus.io/exporter/stackdriver"
    "go.opencensus.io/trace"
)

func main() {
    sd, err := stackdriver.NewExporter(stackdriver.Options{
        ProjectID: "mycoolproject",
    })
    if err != nil {
        // handle error
    }
    defer sd.Flush()
    trace.RegisterExporter(sd)

    sd.StartMetricsExporter()
    defer sd.StopMetricsExporter()

    // Use cloudsqlconn as usual.
    // ...
}
```

## Go Versions Supported

We support the latest four Go versions. Changes in supported Go versions will be
considered a minor and not a major change.

[OpenCensus]: https://opencensus.io/introduction/
[exporter]: https://opencensus.io/exporters/
[Cloud Trace]: https://cloud.google.com/trace
[Cloud Monitoring]: https://cloud.google.com/monitoring
