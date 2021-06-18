# cloud-sql-go-connector
*Warning*: This project is experimental, and is not an officially supported 
Google product.

The _Cloud SQL Go Connector_ provides IAM authorization to an app's connections 
to a Cloud SQL instance. It provides connection level authorization only; it 
_does not_ provide a network path to an instance that doesn't already exist 
(ie. you will still be unable to connect via Private IP without access to the 
correct VPC). For more information, see 
[About the Cloud SQL Auth proxy][about-proxy].

[about-proxy]: https://cloud.google.com/sql/docs/mysql/sql-proxy

The _Cloud SQL Go Connector_ is an experimental new version of the 
[Cloud SQL proxy dialer](). It's API is considered unstable and may change in 
the future. Please use at your own risk. 

[proxy-dialer]: https://github.com/GoogleCloudPlatform/cloudsql-proxy/tree/main/proxy#cloud-sql-proxy-dialer-for-go

## Installation

First, clone this repo into a folder relative to your project:
```sh
git clone https://github.com/kurtisvg/cloud-sql-go-connector.git
```

Next, use a _replace_ directive in your `go.mod` that points to the cloned folder:
```
replace cloud.google.com/cloudsqlconn => ../cloud-sql-go-connector
```

## Usage 

This package provides several functions for authorizing and encrypting 
connections on your behalf. Typically, these functions will pass these 
connections to the driver while interacting with your database.

The instance connection name for your Cloud SQL instance is always in the 
format "project:region:instance".

### Credentials 

This repo uses the [Application Default Credentials (ADC)][adc] strategy for 
providing credentials. Please see the [golang.org/x/oauth2/google][google-auth] 
documentation for more information in how these credentials are sourced. 

// TODO: Mention customizing source

[adc]: https://cloud.google.com/docs/authentication
[google-auth]: https://pkg.go.dev/golang.org/x/oauth2/google#hdr-Credentials

### Using the default Dialer

If you don't need to customize your Dialer's behavior, it's convenient to use 
the package's "Dial" option, which initialized a default dialer for you.  
<details>
  <summary>pgx for Postgres</summary>
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
</details>


### Using DialerOptions

If you need to customize something about the `Dialer`, can and initialize one 
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