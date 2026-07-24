// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package main provides a prototype application for testing and validating
// Cloud SQL Go Connector built-in client metrics exported to Google Cloud Monitoring.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"cloud.google.com/go/cloudsqlconn"
)

func main() {
	// 1. Retrieve the Cloud SQL Instance Connection Name from the environment.
	// Format: "project-id:region:instance-name"
	inst := os.Getenv("CSQL_INSTANCE_CONNECTION_NAME")
	if inst == "" {
		log.Fatal("Error: CSQL_INSTANCE_CONNECTION_NAME environment variable is required.\n" +
			"Example: export CSQL_INSTANCE_CONNECTION_NAME=\"my-project:us-central1:my-instance\"")
	}

	ctx := context.Background()

	// 2. Initialize the Cloud SQL Dialer with custom debug logger and application name.
	// Enabling WithContextDebugLogger allows you to observe internal telemetry logs
	// and OpenTelemetry export operations in stdout.
	logger := &customLogger{}
	d, err := cloudsqlconn.NewDialer(ctx,
		cloudsqlconn.WithContextDebugLogger(logger),
		cloudsqlconn.WithApplicationName("metric-prototype-test"),
	)
	if err != nil {
		log.Fatalf("Failed to initialize Cloud SQL Dialer: %v", err)
	}
	defer d.Close()

	// 3. Dial the Cloud SQL instance.
	// Dials trigger the following metric recordings:
	// - cloudsql.googleapis.com/client/connector/connect_latencies (latency distribution)
	// - cloudsql.googleapis.com/client/connector/open_connections (current active connection gauge increment +1)
	// - cloudsql.googleapis.com/client/connector/open_connection_count (cumulative dial attempts counter)
	fmt.Printf("Dialing Cloud SQL instance: %s ...\n", inst)
	conn, err := d.Dial(ctx, inst)
	if err != nil {
		log.Fatalf("Failed to establish connection: %v", err)
	}
	fmt.Println("Dial successful! Connection established.")

	// 4. Simulate a short workload.
	time.Sleep(2 * time.Second)

	// 5. Close the network connection.
	// Closing the connection triggers:
	// - cloudsql.googleapis.com/client/connector/open_connections (current active connection gauge decrement -1)
	// - cloudsql.googleapis.com/client/connector/closed_connection_count (closed connection counter +1)
	// - cloudsql.googleapis.com/client/connector/connection_durations (connection lifespan distribution in seconds)
	fmt.Println("Closing connection to record closure metrics...")
	err = conn.Close()
	if err != nil {
		log.Fatalf("Failed to close connection: %v", err)
	}
	fmt.Println("Connection closed successfully!")

	// 6. CRITICAL WAITING STEP FOR OPENTELEMETRY EXPORTER:
	// OpenTelemetry exports metric snapshots periodically every 60 seconds (DefaultExportInterval = 60s).
	// Because the OpenTelemetry background meter provider flushes metrics on a 60s ticker,
	// we must keep the main process alive for >60s (75 seconds) to ensure the batch exporter sends
	// the collected metrics to Cloud Monitoring before the application exits.
	fmt.Println("\n==========================================================================")
	fmt.Println("Waiting 75 seconds for the 60-second periodic metric exporter to run...")
	fmt.Println("Do not kill this process until export completes!")
	fmt.Println("==========================================================================")

	time.Sleep(75 * time.Second)
	fmt.Println("\nFinished waiting! Metric export completed. Exiting now.")
	fmt.Println("Check Google Cloud Monitoring Metrics Explorer under 'cloudsql.googleapis.com/client/connector/'.")
}

// customLogger implements the cloudsqlconn.ContextLogger interface to dump
// verbose debug logs to stderr.
type customLogger struct{}

// Debugf formats and logs debug output with a timestamp.
func (c *customLogger) Debugf(_ context.Context, format string, args ...interface{}) {
	log.Printf("[DEBUG] "+format, args...)
}
