# Cloud SQL Go Connector - Client Metrics Prototype

This directory contains a prototype harness for testing, validating, and observing the built-in **OpenTelemetry Client Metrics** exported by the Cloud SQL Go Connector to Google Cloud Monitoring (Stackdriver).

---

## 📌 Overview

The metric prototype demonstrates how the Cloud SQL Go Connector captures and exports client-side operational telemetry without requiring external OpenTelemetry collector infrastructure.

### Telemetry Collected

| Metric Name | Type | Description |
| :--- | :--- | :--- |
| `cloudsql.googleapis.com/client/connector/connect_latencies` | Histogram (`Float64`) | Dial latency in milliseconds. |
| `cloudsql.googleapis.com/client/connector/open_connections` | UpDownCounter (`Int64`) | Number of currently active open connections (Gauge). |
| `cloudsql.googleapis.com/client/connector/open_connection_count` | Counter (`Int64`) | Cumulative total dial attempts categorized by `connection_part` and `status`. |
| `cloudsql.googleapis.com/client/connector/closed_connection_count` | Counter (`Int64`) | Cumulative total number of closed connections. |
| `cloudsql.googleapis.com/client/connector/connection_durations` | Histogram (`Float64`) | Connection lifespan in seconds between open and close. |

---

## 🛠️ Prerequisites

1. **Google Cloud Authentication**: Ensure Application Default Credentials (ADC) are configured with appropriate Cloud SQL and Cloud Monitoring write permissions:
   ```bash
   gcloud auth application-default login
   ```
   * **Required IAM Roles**:
     * `Cloud SQL Client` (`roles/cloudsql.client`)
     * `Monitoring Metric Writer` (`roles/monitoring.metricWriter`)

2. **Target Instance Connection Name**: A running Cloud SQL instance identifier formatted as:
   ```
   <PROJECT_ID>:<REGION>:<INSTANCE_NAME>
   ```

---

## 🚀 Running the Prototype

### Option 1: Using the Runner Script (`run.sh`)

Set your instance connection name and execute the runner script:

```bash
export CSQL_INSTANCE_CONNECTION_NAME="my-project:us-central1:my-instance"
./cmd/metric_prototype/run.sh
```

### Option 2: Using `go run` Directly

```bash
export CSQL_INSTANCE_CONNECTION_NAME="my-project:us-central1:my-instance"
go run ./cmd/metric_prototype/main.go
```

---

## ⏱️ Important Note on Metric Export (60-Second Flush Interval)

OpenTelemetry exports metric snapshots periodically every **60 seconds** (`DefaultExportInterval = 60s`). 

Because the connector's internal meter provider runs batch collection on a 60-second timer, `main.go` includes a **75-second wait step** after closing the connection. 

> ⚠️ **Do not terminate the application early.** Let the script finish waiting so that the OpenTelemetry exporter has time to push the time-series points to Cloud Monitoring.

---

## 🔍 Viewing Metrics in Google Cloud Monitoring

1. Open the [Google Cloud Console Metrics Explorer](https://console.cloud.google.com/monitoring/metrics-explorer).
2. Filter target metrics by namespace:
   ```
   cloudsql.googleapis.com/client/connector/
   ```
3. Group or filter by labels:
   * `resource.labels.client_uid`: Unique ID for each Dialer process.
   * `resource.labels.resource_id`: Format `[project_name:instance_name]`.
   * `metric.labels.instance_auth_type`: `built_in` or `iam`.
   * `metric.labels.instance_ip_type`: `public`, `psa`, `psc`.
   * `metric.labels.connection_part`: `client_to_proxy` or `proxy_to_server`.
   * `metric.labels.status`: `success`, `user_error`, `refresh_failed_error`, `unknown_error`, etc.
