<p align="center">
    <a href="https://pkg.go.dev/cloud.google.com/go/cloudsqlconn">
        <img src="docs/images/cloud-sql-go-connector.png" alt="cloud-sql-go-connector image">
    </a>
</p>

<h1 align="center">Cloud SQL Go Connector</h1>

[![CI][ci-badge]][ci-build]
[![Go Reference][pkg-badge]][pkg-docs]

[ci-badge]: https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/actions/workflows/tests.yaml/badge.svg?event=push
[ci-build]: https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/actions/workflows/tests.yaml?query=event%3Apush+branch%3Amain
[pkg-badge]: https://pkg.go.dev/badge/cloud.google.com/go/cloudsqlconn.svg
[pkg-docs]: https://pkg.go.dev/cloud.google.com/go/cloudsqlconn

The _Cloud SQL Go Connector_ is a Cloud SQL connector designed for use with the
Go language. Using a Cloud SQL connector provides the following benefits:

* **IAM Authorization:** uses IAM permissions to control who/what can connect to
  your Cloud SQL instances
* **Improved Security:** uses robust, updated TLS 1.3 encryption and
  identity verification between the client connector and the server-side proxy,
  independent of the database protocol.
* **Convenience:** removes the requirement to use and distribute SSL
  certificates, as well as manage firewalls or source/destination IP addresses.
* (optionally) **IAM DB Authentication:** provides support for
  [Cloud SQL’s automatic IAM DB AuthN][iam-db-authn] feature.

[iam-db-authn]: https://cloud.google.com/sql/docs/postgres/authentication

For users migrating from the Cloud SQL Proxy drivers, see the [migration
guide](./migration-guide.md).

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
format `project:region:instance`.

### APIs and Services

This package requires the following to successfully make Cloud SQL Connections:

- IAM principal (user, service account, etc.) with the
[Cloud SQL Client][client-role] role or equivalent. This IAM principal will
 be used for [credentials](#credentials).
- The [Cloud SQL Admin API][admin-api] to be enabled within your Google Cloud
Project. By default, the API will be called in the project associated with
the IAM principal.

[admin-api]: https://console.cloud.google.com/apis/api/sqladmin.googleapis.com
[client-role]: https://cloud.google.com/sql/docs/mysql/roles-and-permissions

### Credentials

This project uses the [Application Default Credentials (ADC)][adc] strategy for
resolving credentials. Please see [these instructions for how to set your ADC][set-adc]
(Google Cloud Application vs Local Development, IAM user vs service account credentials),
or consult the [golang.org/x/oauth2/google][google-auth] documentation.

To explicitly set a specific source for the Credentials, see [Using
Options](#using-options) below.

[adc]: https://cloud.google.com/docs/authentication#adc
[set-adc]: https://cloud.google.com/docs/authentication/provide-credentials-adc
[google-auth]: https://pkg.go.dev/golang.org/x/oauth2/google#hdr-Credentials

### Connecting to a database

#### Postgres

Postgres users have the option of using the `database/sql` interface or
using [pgx][] directly. See [pgx's advice on which to choose][pgx-advice].

[pgx]: https://github.com/jackc/pgx
[pgx-advice]: https://github.com/jackc/pgx#choosing-between-the-pgx-and-databasesql-interfaces

##### Using the dialer with pgx

To use the dialer with [pgx][], we recommend using connection pooling with
[pgxpool](https://pkg.go.dev/github.com/jackc/pgx/v4/pgxpool) by configuring
a [Config.DialFunc][dial-func] like so:

``` go
import (
    "context"
    "net"

    "cloud.google.com/go/cloudsqlconn"
    "github.com/jackc/pgx/v4/pgxpool"
)

func connect() {
    // Configure the driver to connect to the database
    dsn := "user=myuser password=mypass dbname=mydb sslmode=disable"
    config, err := pgxpool.ParseConfig(dsn)
    if err != nil {
        /* handle error */
    }

    // Create a new dialer with any options
    d, err := cloudsqlconn.NewDialer(context.Background())
    if err != nil {
        /* handle error */
    }

    // Tell the driver to use the Cloud SQL Go Connector to create connections
    config.ConnConfig.DialFunc = func(ctx context.Context, _ string, instance string) (net.Conn, error) {
        return d.Dial(ctx, "project:region:instance")
    }

    // Interact with the driver directly as you normally would
    conn, err := pgxpool.ConnectConfig(context.Background(), config)
    if err != nil {
        /* handle error */
    }

    // call cleanup when you're done with the database connection
    cleanup := func() error { return d.Close() }
    // ... etc
}
```

[dial-func]: https://pkg.go.dev/github.com/jackc/pgconn#Config

##### Using the dialer with `database/sql`

To use `database/sql`, call `pgxv4.RegisterDriver` with any necessary Dialer
configuration. Note: the connection string must use the keyword/value format
with host set to the instance connection name. The returned `cleanup` func
will stop the dialer's background refresh goroutine and so should only be called
when you're done with the `Dialer`.

``` go
import (
    "database/sql"

    "cloud.google.com/go/cloudsqlconn"
    "cloud.google.com/go/cloudsqlconn/postgres/pgxv4"
)

func connect() {
    cleanup, err := pgxv4.RegisterDriver("cloudsql-postgres", cloudsqlconn.WithIAMAuthN())
    if err != nil {
        // ... handle error
    }
    // call cleanup when you're done with the database connection
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
configuration. The returned `cleanup` func
will stop the dialer's background refresh goroutine and so should only be called
when you're done with the `Dialer`.

```go
import (
    "database/sql"

    "cloud.google.com/go/cloudsqlconn"
    "cloud.google.com/go/cloudsqlconn/mysql/mysql"
)

func connect() {
    cleanup, err := mysql.RegisterDriver("cloudsql-mysql", cloudsqlconn.WithCredentialsFile("key.json"))
    if err != nil {
        // ... handle error
    }
    // call cleanup when you're done with the database connection
    defer cleanup()

    db, err := sql.Open(
        "cloudsql-mysql",
        "myuser:mypass@cloudsql-mysql(project:region:instance)/mydb",
    )
    // ... etc
}
```

#### SQL Server

To use `database/sql`, use `mssql.RegisterDriver` with any necessary Dialer
configuration. The returned `cleanup` func
will stop the dialer's background refresh goroutine and so should only be called
when you're done with the `Dialer`.

``` go
import (
    "database/sql"

    "cloud.google.com/go/cloudsqlconn"
    "cloud.google.com/go/cloudsqlconn/sqlserver/mssql"
)

func connect() {
    cleanup, err := mssql.RegisterDriver("cloudsql-sqlserver", cloudsqlconn.WithCredentialsFile("key.json"))
    if err != nil {
        // ... handle error
    }
    // call cleanup when you're done with the database connection
    defer cleanup()

    db, err := sql.Open(
        "cloudsql-sqlserver",
        "sqlserver://user:password@localhost?database=mydb&cloudsql=project:region:instance",
    )
    // ... etc
}
```

### Using Options

If you need to customize something about the `Dialer`, you can initialize
directly with `NewDialer`:

```go
d, err := cloudsqlconn.NewDialer(
    ctx,
    cloudsqlconn.WithCredentialsFile("key.json"),
)
if err != nil {
    log.Fatalf("unable to initialize dialer: %s", err)
}

conn, err := d.Dial(ctx, "project:region:instance")
```

For a full list of customizable behavior, see Option.

### Using DialOptions

If you want to customize things about how the connection is created, use
`Option`:

```go
conn, err := d.Dial(
    ctx,
    "project:region:instance",
    cloudsqlconn.WithPrivateIP(),
)
```

You can also use the `WithDefaultDialOptions` Option to specify
DialOptions to be used by default:

```go
d, err := cloudsqlconn.NewDialer(
    ctx,
    cloudsqlconn.WithDefaultDialOptions(
        cloudsqlconn.WithPrivateIP(),
    ),
)
```

### Enabling Metrics and Tracing

This library includes support for metrics and tracing using [OpenCensus][].
To enable metrics or tracing, you need to configure an [exporter][].
OpenCensus supports many backends for exporters.

Supported metrics include:

- `cloudsqlconn/dial_latency`: The distribution of dialer latencies (ms)
- `cloudsqlconn/open_connections`: The current number of open Cloud SQL
  connections
- `cloudsqlconn/dial_failure_count`: The number of failed dial attempts
- `cloudsqlconn/refresh_success_count`: The number of successful certificate
  refresh operations
- `cloudsqlconn/refresh_failure_count`: The number of failed refresh
  operations.

Supported traces include:

- `cloud.google.com/go/cloudsqlconn.Dial`: The dial operation including
  refreshing an ephemeral certificate and connecting the instance
- `cloud.google.com/go/cloudsqlconn/internal.InstanceInfo`: The call to retrieve
  instance metadata (e.g., database engine type, IP address, etc)
- `cloud.google.com/go/cloudsqlconn/internal.Connect`: The connection attempt
  using the ephemeral certificate
- SQL Admin API client operations

For example, to use [Cloud Monitoring][] and [Cloud Trace][], you would
configure an exporter like so:

```golang
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

We test and support at minimum, the latest three Go versions. Changes in 
supported Go versions will be considered a minor change, and will be listed in
the release notes.

### Release cadence
This project aims for a release on at least a monthly basis. If no new features
or fixes have been added, a new PATCH version with the latest dependencies is
released.
