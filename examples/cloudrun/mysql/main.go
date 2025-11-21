// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"

	"cloud.google.com/go/cloudsqlconn"
	"github.com/go-sql-driver/mysql"
)

var (
	dbPassword *sql.DB
	dbIAM      *sql.DB
	// dbPasswordOnce guards the initialization of the password-authenticated database connection.
	dbPasswordOnce sync.Once
	// dbIAMOnce guards the initialization of the IAM-authenticated database connection.
	dbIAMOnce sync.Once
)

// Connector is thread-safe and should be reused.
var (
	dialer     *cloudsqlconn.Dialer
	dialerOnce sync.Once
)

func getDialer() (*cloudsqlconn.Dialer, error) {
	var err error
	dialerOnce.Do(func() {
		dialer, err = cloudsqlconn.NewDialer(context.Background(), cloudsqlconn.WithLazyRefresh())
	})
	return dialer, err
}

// connectWithPassword initializes the connector and password db if necessary, then returns a connection.
func connectWithPassword() (*sql.DB, error) {
	var err error
	dbPasswordOnce.Do(func() {
		var d *cloudsqlconn.Dialer
		d, err = getDialer()
		if err != nil {
			return
		}

		password := os.Getenv("DB_PASSWORD")
		dbUser := os.Getenv("DB_USER")
		dbName := os.Getenv("DB_NAME")
		ipType := os.Getenv("IP_TYPE")

		opts := []cloudsqlconn.DialOption{}
		if ipType == "PRIVATE" {
			opts = append(opts, cloudsqlconn.WithPrivateIP())
		} else if ipType == "PSC" {
            opts = append(opts, cloudsqlconn.WithPSC())
        }

		mysql.RegisterDialContext("cloudsql-password",
			func(ctx context.Context, addr string) (net.Conn, error) {
				return d.Dial(ctx, os.Getenv("INSTANCE_CONNECTION_NAME"), opts...)
			})

		dsn := fmt.Sprintf("%s:%s@cloudsql-password(%s)/%s",
			dbUser, password, os.Getenv("INSTANCE_CONNECTION_NAME"), dbName)

		dbPassword, err = sql.Open("mysql", dsn)
	})
	return dbPassword, err
}

func connectWithIAM() (*sql.DB, error) {
	var err error
	dbIAMOnce.Do(func() {
		var d *cloudsqlconn.Dialer
		d, err = getDialer()
		if err != nil {
			return
		}

		// IAM auth needs `WithIAMAuthN` option in the dialer OR `enable_iam_auth` in Python.
		// In Go connector, `WithIAMAuthN` is a Option (for NewDialer).
		// `WithDialIAMAuthN` is a DialOption (for Dial) which takes a boolean.

		ipType := os.Getenv("IP_TYPE")
		opts := []cloudsqlconn.DialOption{
			cloudsqlconn.WithDialIAMAuthN(true),
		}
		if ipType == "PRIVATE" {
			opts = append(opts, cloudsqlconn.WithPrivateIP())
		} else if ipType == "PSC" {
            opts = append(opts, cloudsqlconn.WithPSC())
        }

		mysql.RegisterDialContext("cloudsql-iam",
			func(ctx context.Context, addr string) (net.Conn, error) {
				return d.Dial(ctx, os.Getenv("INSTANCE_CONNECTION_NAME"), opts...)
			})

		dbUser := os.Getenv("DB_IAM_USER")
		dbName := os.Getenv("DB_NAME")

		// For IAM, password is technically not used but the driver might expect something or ignore it.
		// Go MySQL driver usually takes "user:password".
		// With Cloud SQL IAM, the password is usually ignored or handled by the connector (it exchanges token).

		dsn := fmt.Sprintf("%s@cloudsql-iam(%s)/%s",
			dbUser, os.Getenv("INSTANCE_CONNECTION_NAME"), dbName)

		dbIAM, err = sql.Open("mysql", dsn)
	})
	return dbIAM, err
}

func passwordAuthIndex(w http.ResponseWriter, r *http.Request) {
	db, err := connectWithPassword()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error connecting to database (password): %v", err), 500)
		return
	}

	// Verify connection
	if err := db.Ping(); err != nil {
		http.Error(w, fmt.Sprintf("Error pinging database (password): %v", err), 500)
		return
	}

	rows, err := db.Query("SELECT 1")
	if err != nil {
		http.Error(w, fmt.Sprintf("Error querying database (password): %v", err), 500)
		return
	}
	defer rows.Close()

	var result int
	for rows.Next() {
		if err := rows.Scan(&result); err != nil {
			http.Error(w, fmt.Sprintf("Error scanning result (password): %v", err), 500)
			return
		}
	}

	fmt.Fprintf(w, "Database connection successful (password authentication), result: [[%d]]", result)
}

func iamAuthIndex(w http.ResponseWriter, r *http.Request) {
	db, err := connectWithIAM()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error connecting to database (IAM): %v", err), 500)
		return
	}

	if err := db.Ping(); err != nil {
		http.Error(w, fmt.Sprintf("Error pinging database (IAM): %v", err), 500)
		return
	}

	rows, err := db.Query("SELECT 1")
	if err != nil {
		http.Error(w, fmt.Sprintf("Error querying database (IAM): %v", err), 500)
		return
	}
	defer rows.Close()

	var result int
	for rows.Next() {
		if err := rows.Scan(&result); err != nil {
			http.Error(w, fmt.Sprintf("Error scanning result (IAM): %v", err), 500)
			return
		}
	}

	fmt.Fprintf(w, "Database connection successful (IAM authentication), result: [[%d]]", result)
}

func main() {
	http.HandleFunc("/", passwordAuthIndex)
	http.HandleFunc("/iam", iamAuthIndex)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Listening on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}
