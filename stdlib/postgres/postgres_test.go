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
