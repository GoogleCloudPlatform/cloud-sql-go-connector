# cloud-sql-go-connector
*Warning*: This project is in Public Preview, and may contain breaking changes
before it becomes Generally Available.

![CI](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/actions/workflows/tests.yaml/badge.svg)
[![Go Reference](https://pkg.go.dev/badge/cloud.google.com/go/cloudsqlconn.svg)](https://pkg.go.dev/cloud.google.com/go/cloudsqlconn)

The _Cloud SQL Go Connector_ is a Cloud SQL connector designed for use with the
Go language. Using a Cloud SQL connector provides the following benefits:
* **IAM Authorization:** uses IAM permissions to control who/what can connect to
  your Cloud SQL instances
* **Improved Security:** uses robust, updated TLS 1.3 encryption and
  identity verification between the client connector and the server-side proxy,
  independent of the database protocol.
* **Convenience:** removes the requirement to use and distribute SSL
  certificates, as well as manage firewalls or source/destination IP addresses.
* (optionally) **IAM DB Authenticiation:** provides support for
  [Cloud SQL’s automatic IAM DB AuthN][iam-db-authn] feature.

[iam-db-authn]: https://cloud.google.com/sql/docs/postgres/authentication

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

### Postgres

To use the dialer with [pgx](https://github.com/jackc/pgx), use
[pgxpool](https://pkg.go.dev/github.com/jackc/pgx/v4/pgxpool) by configuring
a [Config.DialFunc][dial-func] like so:

``` go
// Configure the driver to connect to the database
dsn := fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable", pgUser, pgPass, pgDB)
config, err := pgxpool.ParseConfig(dsn)
if err != nil {
    log.Fatalf("failed to parse pgx config: %v", err)
}

// Create a new dialer with any options
d, err := cloudsqlconn.NewDialer(ctx)
if err != nil {
    log.Fatalf("failed to initialize dialer: %v", err)
}
defer d.Close()

// Tell the driver to use the Cloud SQL Go Connector to create connections
config.ConnConfig.DialFunc = func(ctx context.Context, _ string, instance string) (net.Conn, error) {
    return d.Dial(ctx, "project:region:instance")
}

// Interact with the dirver directly as you normally would
conn, err := pgxpool.ConnectConfig(context.Background(), config)
if err != nil {
    log.Fatalf("failed to connect: %v", connErr)
}
defer conn.Close()
```

[dial-func]: https://pkg.go.dev/github.com/jackc/pgconn#Config

### MySQL

The [Go MySQL driver][mysql] does not provide a stand-alone interface for
interacting with a database and instead uses `database/sql`. See [the section
below](#MySQL) on how to use the `database/sql` package with a Cloud SQL MySQL
instance.

[mysql]: https://github.com/go-sql-driver/mysql

### SQL Server

[Go-mssql][go-mssqldb] does not provide a stand-alone interface for interacting
with a database and instead uses `database/sql`. See [the section below](#SQL-Server)
on how to use the `database/sql` package with a Cloud SQL SQL Server instance.

[go-mssqldb]: https://github.com/denisenkom/go-mssqldb

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

To use `database/sql`, use `pgxv4.RegisterDriver` with any necessary Dialer
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
    cleanup, err := pgxv4.RegisterDriver("cloudsql-postgres", cloudsqlconn.WithIAMAuthN())
    if err != nil {
        // ... handle error
    }
    defer cleanup()

    db, err := sql.Open(
        "cloudsql-postgres",
        "host=project:region:instance user=myuser password=mypass dbname=mydb sslmode=disable",
	)
    // ... etc
}
```

#### MySQL

To use `database/sql`, use `mysql.RegisterDriver` with any necessary Dialer
configuration.

```go
package foo

import (
    "database/sql"

    "cloud.google.com/go/cloudsqlconn"
    "cloud.google.com/go/cloudsqlconn/mysql/mysql"
)

func Connect() {
    cleanup, err := mysql.RegisterDriver("cloudsql-mysql", cloudsqlconn.WithCredentialsFile("key.json"))
    if err != nil {
        // ... handle error
    }
    defer cleanup()

    db, err := sql.Open(
        "cloudsql-mysql",
        "myuser:mypass@cloudsql-mysql(my-project:us-central1:my-instance)/mydb",
	)
    // ... etc
}
```

### SQL Server

To use `database/sql`, use `sqlserver.RegisterDriver` with any necessary Dialer
configuration.

``` go
package foo

import (
    "database/sql"

    "cloud.google.com/go/cloudsqlconn"
    "cloud.google.com/go/cloudsqlconn/sqlserver"
)

func Connect() {
    cleanup, err := sqlserver.RegisterDriver("cloudsql-sqlserver", cloudsqlconn.WithCredentialsFile("key.json"))
    if err != nil {
        // ... handle error
    }
    defer cleanup()

    db, err := sql.Open(
        "cloudsql-sqlserver",
        "sqlserver://user:password@localhost?database=mydb&cloudsql=my-proj:us-central1:my-inst",
    )
    // ... etc
}
```


### Enabling Metrics and Tracing

This library includes support for metrics and tracing using [OpenCensus][].
To enable metrics or tracing, you need to configure an [exporter][].
OpenCensus supports many backends for exporters.

For example, to use [Cloud Monitoring][] and [Cloud Trace][], you would
configure an exporter like so:

```golang
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
[OpenCensus]: https://opencensus.io/
[exporter]: https://opencensus.io/exporters/
[Cloud Monitoring]: https://cloud.google.com/monitoring
[Cloud Trace]: https://cloud.google.com/trace

## Support policy

### Major version lifecycle

This project uses [semantic versioning](https://semver.org/), and uses the
following lifecycle regarding support for a major version:

**Active** - Active versions get all new features and security fixes (that
wouldn’t otherwise introduce a breaking change). New major versions are
guaranteed to be "active" for a minimum of 1 year.

**Deprecated** - Deprecated versions continue to receive security and critical
bug fixes, but do not receive new features. Deprecated versions will be
supported for 1 year.

**Unsupported** - Any major version that has been deprecated for >=1 year is
considered unsupported.

## Supported Go Versions

We test and support at minimum, the latest three Go versions. Changes in supported Go versions will be
considered a minor change, and will be listed in the realease notes. 

### Release cadence
This project aims for a release on at least a monthly basis. If no new features
or fixes have been added, a new PATCH version with the latest dependencies is
released.
