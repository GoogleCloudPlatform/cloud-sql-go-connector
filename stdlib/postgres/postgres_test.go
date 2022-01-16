package postgres

import (
	"database/sql"
	"log"
	"time"
)

// Example shows how to use cloudsqlpostgres dialer
func ExamplePostgresConnection() {
	// Note that sslmode=disable is required it does not mean that the connection
	// is unencrypted. All connections via the proxy are completely encrypted.
	db, err := sql.Open(
		"cloudsql-postgres",
		"host=project:region:instance user=postgres dbname=postgres password=password sslmode=disable",
	)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	var now time.Time
	if err := db.QueryRow("SELECT NOW()").Scan(&now); err != nil {
		log.Fatal(err)
	}
	log.Println(now)
}
