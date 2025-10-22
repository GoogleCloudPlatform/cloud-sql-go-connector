// Copyright 2025 Google LLC
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

package tel

import "context"

const (
	meterName             = "alloydb.googleapis.com/client/connector"
	monitoredResource     = "cloudsql.googleapis.com/InstanceClient"
	connectLatency        = "connect_latencies"
	closedConnectionCount = "closed_connection_count"
	openConnections       = "open_connections"

	// The identifier of the GCP project associated with this CSQL resource
	ResourceContainer = "resource_container"
	// The Cloud SQL instance identifier in the format of [project_name:instance_name]
	ResourceID = "resource_id"
	// A unique identifier generated for each Dialer instance
	ClientUID = "client_uid"
	// The application name provided by the user or defaulted by the connector
	ApplicationName = "application_name"
	// Cloud SQL Instance's location  e.g. us-central1
	Region = "region"
	// ClientRegion is the region from which the client is connecting, unknown if not on GCP
	ClientRegion = "client_region"
	// ComputePlatform is the platform on which the client is running, e.g. GCE, GKE, etc.
	ComputePlatform = "compute_platform"
	// Cloud SQL Connector type. "go" in this case.
	ConnectorType = "connector_type"
	// Cloud SQL Connector version
	ConnectorVersion = "connector_version"
	// Database engine type [MySQL, PostgreSQL, SQL Server].
	DatabaseEngineType = "database_engine_type"
	// authType is one of iam or built-in
	authType = "auth_type"
	// IP address type of the connection, one of [public, psa, psc]
	ipType = "ip_type"
	// status indicates whether the dial attempt succeeded or not.
	status = "status"
)

// Config holds all the necessary information to configure a MetricRecorder.
type Config struct {
	// Enabled specifies whether the metrics should be enabled.
	Enabled bool
	// Project id
	ResourceContainer string
	// The Cloud SQL instance identifier in the format of [project_name:instance_name]
	ResourceID string
	// A unique identifier generated for each Dialer instance
	ClientUID string
	// The application name provided by the user or defaulted by the connector
	ApplicationName string
	// Cloud SQL Instance's location  e.g. us-central1
	Region string
	// ClientRegion is the region from which the client is connecting, unknown if not on GCP
	ClientRegion string
	// ComputePlatform is the platform on which the client is running, e.g. GCE, GKE, etc.
	ComputePlatform string
	// Cloud SQL Connector type. "go" in this case.
	ConnectorType string
	// Cloud SQL Connector version
	ConnectorVersion string
	// Database engine type [MySQL, PostgreSQL, SQL Server].
	DatabaseEngineType string
}

// Attributes holds all the various pieces of metadata to attach to a metric.
type Attributes struct {
	// IAMAuthN specifies whether IAM authentication is enabled.
	IAMAuthN bool
	// UserAgent is the full user-agent of the alloydbconn.Dialer.
	UserAgent string
	// CacheHit specifies whether connection info was present in the cache.
	CacheHit bool
	// DialStatus specifies the result of the dial attempt.
	DialStatus string
}

// MetricRecorder defines the interface for recording metrics related to the
// internal operations of alloydbconn.Dialer.
type MetricRecorder interface {
	RecordOpenConnection(context.Context, Attributes)
	RecordClosedConnectionCount(context.Context, Attributes)
	RecordConnectLatencies(context.Context, Attributes)
}
