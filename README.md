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
[Cloud SQL proxy dialer](dialer). Its API is considered unstable and may change 
in the future. Please use at your own risk. 

[proxy-dialer]: https://github.com/GoogleCloudPlatform/cloudsql-proxy/tree/main/proxy#cloud-sql-proxy-dialer-for-go

## Installation

First, clone this repo into a folder relative to your project:
```sh
git clone https://github.com/kurtisvg/cloud-sql-go-connector.git
```

Next, use a _replace_ directive in your `go.mod` that points to the cloned
folder:
```
replace cloud.google.com/cloudsqlconn => ../cloud-sql-go-connector
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
DialerOptions](#using-dialeroptions) below.

[adc]: https://cloud.google.com/docs/authentication
[google-auth]: https://pkg.go.dev/golang.org/x/oauth2/google#hdr-Credentials

### Using the default Dialer

If you don't need to customize your Dialer's behavior, it is convenient to use
the package's "Dial" option, which initializes a default dialer for you. 

#### pgx for Postgres

  Use the [pgConn.DialFunc field][pgconn-cfg] to create connections:

  ```go
  // Configure the driver to connect to the database
  dsn := fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable", pgUser, pgPass, pgDb)
  config, err := pgx.ParseConfig(dsn)
  if err != nil {
      t.Fatalf("failed to parse pgx config: %v", err)
  }

  // Tell the driver to use the Cloud SQL Go Connector to create connections
  config.DialFunc = func(ctx context.Context, network string, instance string) (net.Conn, error) {
      return cloudsqlconn.Dial(ctx, "project:region:instance")
  }

 // Interact with the driver directly as you normally would
  conn, connErr := pgx.ConnectConfig(ctx, config)
  if connErr != nil {
      t.Fatalf("failed to connect: %s", connErr)
  }
  defer conn.Close(ctx)
  ```
  [pgconn-cfg]: https://pkg.go.dev/github.com/jackc/pgconn#Config



### Using DialerOptions

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

For a full list of customizable behavior, see DialerOptions.

### Using DialOptions

If you want to customize things about how the connection is created, use 
`DialerOptions`:
```go
conn, err := myDialer.Dial(
    ctx, 
    "project:region:instance",
    cloudsqlconn.WithPrivateIP(),
)
```

You can also use the `WithDefaultDialOptions` DialerOption to specify
DialOptions to be used by default:
```go
myDialer, err := cloudsqlconn.NewDialer(
    ctx,
    cloudsqlconn.WithDefaultDialOptions(
        cloudsqlconn.WithPrivateIP(),
    ),
)
```