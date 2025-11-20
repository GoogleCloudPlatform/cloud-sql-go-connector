package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"

	"cloud.google.com/go/cloudsqlconn"
	"cloud.google.com/go/cloudsqlconn/sqlserver/mssql"
)

var (
	db *sql.DB
	// dbOnce guards the initialization of the database connection.
	dbOnce sync.Once
)

// connectWithPassword initializes the connector and db if necessary, then returns a connection.
func connectWithPassword() (*sql.DB, error) {
	var err error
	dbOnce.Do(func() {
		password := os.Getenv("DB_PASSWORD")
		dbUser := os.Getenv("DB_USER")
		dbName := os.Getenv("DB_NAME")
		instanceConnectionName := os.Getenv("INSTANCE_CONNECTION_NAME")
		ipType := os.Getenv("IP_TYPE")

		opts := []cloudsqlconn.Option{cloudsqlconn.WithLazyRefresh()}
		if ipType == "PRIVATE" {
			opts = append(opts, cloudsqlconn.WithDefaultDialOptions(cloudsqlconn.WithPrivateIP()))
		} else if ipType == "PSC" {
            opts = append(opts, cloudsqlconn.WithDefaultDialOptions(cloudsqlconn.WithPSC()))
        }

		// Register the driver with options.
		// Note: RegisterDriver handles dialer creation internally.
		cleanup, err := mssql.RegisterDriver("cloudsql-sqlserver", opts...)
		if err != nil {
			return
		}
		// We usually should defer cleanup, but in a lazy singleton it's tricky.
		// For now we accept it will live until process termination.
		_ = cleanup

		dsn := fmt.Sprintf("sqlserver://%s:%s@localhost?database=%s&cloudsql=%s",
			dbUser, password, dbName, instanceConnectionName)

		db, err = sql.Open("cloudsql-sqlserver", dsn)
	})
	return db, err
}

func index(w http.ResponseWriter, r *http.Request) {
	db, err := connectWithPassword()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error connecting to database: %v", err), 500)
		return
	}

	if err := db.Ping(); err != nil {
		http.Error(w, fmt.Sprintf("Error pinging database: %v", err), 500)
		return
	}

	rows, err := db.Query("SELECT 1")
	if err != nil {
		http.Error(w, fmt.Sprintf("Error querying database: %v", err), 500)
		return
	}
	defer rows.Close()

	var result int
	for rows.Next() {
		if err := rows.Scan(&result); err != nil {
			http.Error(w, fmt.Sprintf("Error scanning result: %v", err), 500)
			return
		}
	}

	fmt.Fprintf(w, "Database connection successful, result: [[%d]]", result)
}

func main() {
	http.HandleFunc("/", index)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Listening on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}
