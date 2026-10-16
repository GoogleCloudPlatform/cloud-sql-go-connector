// Copyright 2026 Google LLC
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

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"cloud.google.com/go/cloudsqlconn/debug"
	"cloud.google.com/go/cloudsqlconn/errtype"
	"cloud.google.com/go/compute/metadata"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"

	monitoring "cloud.google.com/go/monitoring/apiv3/v2"
	cmexporter "github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

const (
	meterName             = "cloudsql.googleapis.com/client/connector"
	monitoredResource     = "cloudsql.googleapis.com/InstanceClient"
	connectLatency        = "connect_latencies" // dial latency
	closedConnectionCount = "closed_connection_count"
	openConnections       = "open_connections"
	connectionDurations   = "connection_durations"
	openConnectionCount   = "open_connection_count"
	connectionPart        = "connection_part"

	// ResourceContainer is the identifier of the GCP project associated with this CSQL resource.
	ResourceContainer = "resource_container"
	// ResourceID is the Cloud SQL instance identifier in the format of [project_name:instance_name].
	ResourceID = "resource_id"
	// ClientUID is a unique identifier generated for each Dialer instance.
	ClientUID = "client_uid"
	// ApplicationName is the application name provided by the user or defaulted by the connector.
	ApplicationName = "application_name"
	// Region is the Cloud SQL Instance's location e.g. us-central1.
	Region = "region"
	// ClientRegion is the region from which the client is connecting, unknown if not on GCP
	ClientRegion = "client_region"
	// ComputePlatform is the platform on which the client is running, e.g. GCE, GKE, etc.
	ComputePlatform = "compute_platform"
	// ConnectorType is the Cloud SQL Connector type. "go" in this case.
	ConnectorType = "connector_type"
	// ConnectorVersion is the Cloud SQL Connector version.
	ConnectorVersion = "connector_version"
	// DatabaseEngineType is the database engine type [MySQL, PostgreSQL, SQL Server].
	DatabaseEngineType = "database_engine_type"
	// authType is one of iam or built-in
	authType = "instance_auth_type"
	// IP address type of the connection, one of [public, psa, psc]
	ipType = "instance_ip_type"
	// status indicates whether the dial attempt succeeded or not.
	status = "status"
	// ConnectSuccess indicates the dial attempt succeeded.
	ConnectSuccess = "success"
	// ConnectError indicates the dial attempt errors out.
	ConnectError = "error"
	// RefreshAheadType indicates the dialer is using a refresh ahead cache.
	RefreshAheadType = "refresh_ahead"
	// RefreshLazyType indicates the dialer is using a lazy cache.
	RefreshLazyType = "lazy"

	// UnknownValue is used for any label whose value could not be determined.
	// All enum-like label values are lowercase snake_case, matching the
	// published metric descriptors and the AlloyDB connector.
	UnknownValue = "unknown"

	// ConnectorTypeGo is the connector_type value for the Go connector.
	ConnectorTypeGo = "go"
	// ConnectorTypeAuthProxy is the connector_type value for the Cloud SQL
	// Auth Proxy, which embeds the Go connector.
	ConnectorTypeAuthProxy = "auth_proxy"

	// PlatformGKE is the compute_platform value for Google Kubernetes Engine.
	PlatformGKE = "gke"
	// PlatformCloudRun is the compute_platform value for Cloud Run.
	PlatformCloudRun = "cloud_run"
	// PlatformAppEngine is the compute_platform value for App Engine.
	PlatformAppEngine = "app_engine"
	// PlatformCloudFunctions is the compute_platform value for Cloud Functions.
	PlatformCloudFunctions = "cloud_functions"
	// PlatformGCE is the compute_platform value for Compute Engine.
	PlatformGCE = "gce"

	// EngineMySQL is the database_engine_type value for MySQL.
	EngineMySQL = "mysql"
	// EnginePostgreSQL is the database_engine_type value for PostgreSQL.
	EnginePostgreSQL = "postgresql"
	// EngineSQLServer is the database_engine_type value for SQL Server.
	EngineSQLServer = "sqlserver"

	// IPTypePublic is the instance_ip_type value for public IP connections.
	IPTypePublic = "public"
	// IPTypePrivate is the instance_ip_type value for private IP (PSA)
	// connections.
	IPTypePrivate = "private"
	// IPTypePSC is the instance_ip_type value for Private Service Connect
	// connections.
	IPTypePSC = "psc"
	// IPTypeAuto is the instance_ip_type value when the connection type was
	// requested as AutoIP (public if available, otherwise private).
	IPTypeAuto = "auto"
	// IPTypeSQLData is the instance_ip_type value for connections through the
	// SQL Data endpoint.
	IPTypeSQLData = "sql_data"
)

// Config holds all the necessary information to configure a MetricRecorder.
type Config struct {
	// Enabled specifies whether the metrics should be enabled.
	Enabled bool
	// Version is the version of the cloudsqlconn.Dialer.
	Version string
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

// ConnectorTypeValue returns the connector type based on the user agent.
func ConnectorTypeValue(userAgent string) string {
	if strings.Contains(userAgent, "cloud-sql-proxy") {
		return ConnectorTypeAuthProxy
	}
	return ConnectorTypeGo
}

// IPTypeValue maps a dial connection type (e.g. cloudsql.PublicIP) to the
// instance_ip_type label value.
func IPTypeValue(connectionType string) string {
	switch strings.ToUpper(connectionType) {
	case "PUBLIC":
		return IPTypePublic
	case "PRIVATE":
		return IPTypePrivate
	case "PSC":
		return IPTypePSC
	case "AUTOIP":
		return IPTypeAuto
	case "SQLDATA":
		return IPTypeSQLData
	case "":
		return UnknownValue
	default:
		return strings.ToLower(connectionType)
	}
}

// AuthTypeValue returns the auth type string based on whether IAM Authn is enabled.
func AuthTypeValue(iamAuthn bool) string {
	if iamAuthn {
		return "iam"
	}
	return "built_in"
}

// DetectClientRegion returns the client region from GCP metadata if running on GCE/GKE/Cloud Run.
// Any panic or error fails silently and returns UnknownValue.
func DetectClientRegion() (region string) {
	// Safeguard against unexpected panics to prevent hard crashes in client applications.
	defer func() {
		if r := recover(); r != nil {
			region = UnknownValue
		}
	}()
	if !metadata.OnGCE() {
		return UnknownValue
	}
	zone, err := metadata.Zone()
	if err != nil || zone == "" {
		return UnknownValue
	}
	if idx := strings.LastIndex(zone, "-"); idx != -1 {
		return strings.ToLower(zone[:idx])
	}
	return strings.ToLower(zone)
}

// DetectComputePlatform detects the GCP compute platform environment.
// Any panic or error fails silently and returns UnknownValue.
func DetectComputePlatform() (platform string) {
	switch {
	case os.Getenv("KUBERNETES_SERVICE_HOST") != "":
		return PlatformGKE
	case os.Getenv("K_SERVICE") != "":
		return PlatformCloudRun
	case os.Getenv("GAE_SERVICE") != "":
		return PlatformAppEngine
	case os.Getenv("FUNCTION_NAME") != "":
		return PlatformCloudFunctions
	case metadata.OnGCE():
		return PlatformGCE
	default:
		return UnknownValue
	}
}

// DetectDatabaseEngineType detects the database engine type from a Cloud SQL DBVersion string.
// Any panic or error fails silently and returns UnknownValue.
func DetectDatabaseEngineType(dbVersion string) (engine string) {
	switch {
	case strings.HasPrefix(dbVersion, "MYSQL"):
		return EngineMySQL
	case strings.HasPrefix(dbVersion, "POSTGRES"):
		return EnginePostgreSQL
	case strings.HasPrefix(dbVersion, "SQLSERVER"):
		return EngineSQLServer
	default:
		return UnknownValue
	}
}

// Attributes holds all the various pieces of metadata to attach to a metric.
type Attributes struct {
	// IAMAuthN specifies whether IAM authentication is enabled.
	IAMAuthN bool
	// CacheHit specifies whether connection info was present in the cache.
	CacheHit bool
	// DialStatus specifies the result of the dial attempt.
	DialStatus string
	// IpType specifies IP address type of the connection, one of [public, psa, psc].
	IPType string
	// RefreshType specifies the type of cache in use (e.g., refresh ahead or
	// lazy).
	RefreshType string
	// ipType specifies IP address type of the connection, one of [public, psa, psc].
	IPAddressType string
	// ConnectionPart specifies which part of the connection errors out, one of [client_to_proxy, proxy_to_server].
	ConnectionPart string
	// AttemptStatus specifies the detailed status of the dial attempt.
	AttemptStatus string
}

// ClassifyDialError classifies an error during a connection attempt into connection_part and status labels.
func ClassifyDialError(err error) (string, string) {
	if err == nil {
		return "", ConnectSuccess
	}
	var configErr *errtype.ConfigError
	if errors.As(err, &configErr) {
		return "client_to_proxy", "user_error"
	}
	var refreshErr *errtype.RefreshError
	if errors.As(err, &refreshErr) {
		return "client_to_proxy", "refresh_failed_error"
	}
	// TODO: Replace this fallback with structural error tracking across callsites
	// to accurately map granular status codes and provide more accurate "connection_part"
	// detection (especially distinguishing errors in the proxy_to_server path)
	// without relying on string matching.
	return UnknownValue, "unknown_error"
}

// MetricRecorder defines the interface for recording metrics related to the
// internal operations of cloudsqlconn.Dialer.
type MetricRecorder interface {
	RecordOpenConnection(context.Context, Attributes)
	RecordClosedConnection(context.Context, Attributes)
	RecordClosedConnectionCount(context.Context, Attributes)
	RecordConnectLatencies(context.Context, Attributes, int64)
	RecordConnectionDuration(context.Context, Attributes, float64)
	RecordOpenConnectionCount(context.Context, Attributes)
	DatabaseEngine() string
	// Shutdown flushes any buffered metrics and stops the periodic export.
	// It must be called when the recorder is no longer needed, otherwise
	// metrics recorded since the last export are lost.
	Shutdown(context.Context) error
}

// DefaultExportInterval is the interval that the metric exporter runs. It
// should always be 60s. This value is exposed as a var to faciliate testing.
var DefaultExportInterval = 60 * time.Second

// NewMetricRecorder creates a MetricRecorder. When the configuration is not
// enabled, a null recorder is returned instead.
func NewMetricRecorder(ctx context.Context, l debug.ContextLogger, cl *monitoring.MetricClient, cfg Config) MetricRecorder {
	if !cfg.Enabled {
		l.Debugf(ctx, "disabling built-in metrics")
		return NullMetricRecorder{}
	}
	if cl == nil {
		l.Debugf(ctx, "metric client is nil, disabling built-in metrics")
		return NullMetricRecorder{}
	}

	eopts := []cmexporter.Option{
		cmexporter.WithCreateServiceTimeSeries(),
		cmexporter.WithProjectID(cfg.ResourceContainer),
		cmexporter.WithMonitoringClient(cl),
		cmexporter.WithMetricDescriptorTypeFormatter(func(m metricdata.Metrics) string {
			return "cloudsql.googleapis.com/client/connector/" + m.Name
		}),
		cmexporter.WithMonitoredResourceDescription(monitoredResource, []string{
			ResourceContainer, ResourceID, ClientUID, ApplicationName, Region, ClientRegion,
			ComputePlatform, ConnectorType, ConnectorVersion, DatabaseEngineType,
		}),
	}
	exp, err := cmexporter.New(eopts...)
	if err != nil {
		l.Debugf(ctx, "built-in metrics exporter failed to initialize: %v", err)
		return NullMetricRecorder{}
	}
	// A Dialer creates one recorder (provider + reader + exporter) per
	// instance, but all of them share the single MetricClient passed in via
	// WithMonitoringClient. The Cloud Monitoring exporter's Shutdown closes
	// that client as if it owned it, which would break every other recorder
	// still using it (observed as "grpc: the client connection is closing"
	// when a recorder is replaced or when Close flushes multiple instances).
	// sharedClientExporter delegates everything to the real exporter except
	// Shutdown, which is a no-op. The periodic reader still performs its
	// final collect-and-export before calling Shutdown, so flushing works;
	// the Dialer closes the shared client once after all recorders are
	// shut down.
	sharedExp := sharedClientExporter{Exporter: exp}

	res := resource.NewWithAttributes(monitoredResource,
		// The gcp.resource_type is a special attribute that the exporter
		// transforms into the MonitoredResource field.
		attribute.String("gcp.resource_type", monitoredResource),
		attribute.String(ResourceContainer, cfg.ResourceContainer),
		attribute.String(ResourceID, cfg.ResourceID),
		attribute.String(ClientUID, cfg.ClientUID),
		attribute.String(ApplicationName, cfg.ApplicationName),
		attribute.String(Region, cfg.Region),
		attribute.String(ClientRegion, cfg.ClientRegion),
		attribute.String(ComputePlatform, cfg.ComputePlatform),
		attribute.String(ConnectorType, cfg.ConnectorType),
		attribute.String(ConnectorVersion, cfg.ConnectorVersion),
		attribute.String(DatabaseEngineType, cfg.DatabaseEngineType),
	)

	p := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(
			sharedExp,
			// The periodic reader runs every 60 seconds by default, but set
			// the value anyway to be defensive.
			sdkmetric.WithInterval(DefaultExportInterval),
		)),
		sdkmetric.WithResource(res),
	)
	m := p.Meter(meterName, metric.WithInstrumentationVersion(cfg.Version))

	mConnectLatency, err := m.Float64Histogram(connectLatency)
	if err != nil {
		_ = p.Shutdown(ctx)
		l.Debugf(ctx, "built-in metrics exporter failed to initialize dial latency metric: %v", err)
		return NullMetricRecorder{}
	}
	mOpenConns, err := m.Int64UpDownCounter(openConnections)
	if err != nil {
		_ = p.Shutdown(ctx)
		l.Debugf(ctx, "built-in metrics exporter failed to initialize open connections metric: %v", err)
		return NullMetricRecorder{}
	}
	mClosedConnectionCount, err := m.Int64Counter(closedConnectionCount)
	if err != nil {
		_ = p.Shutdown(ctx)
		l.Debugf(ctx, "built-in metrics exporter failed to initialize refresh count metric: %v", err)
		return NullMetricRecorder{}
	}
	mConnectionDuration, err := m.Float64Histogram(connectionDurations, metric.WithUnit("s"))
	if err != nil {
		_ = p.Shutdown(ctx)
		l.Debugf(ctx, "built-in metrics exporter failed to initialize connection duration metric: %v", err)
		return NullMetricRecorder{}
	}
	mOpenConnectionCount, err := m.Int64Counter(openConnectionCount)
	if err != nil {
		_ = p.Shutdown(ctx)
		l.Debugf(ctx, "built-in metrics exporter failed to initialize open connection count metric: %v", err)
		return NullMetricRecorder{}
	}
	return &metricRecorder{
		exporter:               sharedExp,
		provider:               p,
		dialerID:               cfg.ClientUID,
		dbEngineType:           cfg.DatabaseEngineType,
		mClosedConnectionCount: mClosedConnectionCount,
		mConnectLatency:        mConnectLatency,
		mConnectionDuration:    mConnectionDuration,
		mOpenConns:             mOpenConns,
		mOpenConnectionCount:   mOpenConnectionCount,
	}
}

// metricRecorder holds the various counters that track internal operations.
type metricRecorder struct {
	exporter               sdkmetric.Exporter
	provider               *sdkmetric.MeterProvider
	dialerID               string
	dbEngineType           string
	mClosedConnectionCount metric.Int64Counter
	mConnectLatency        metric.Float64Histogram
	mConnectionDuration    metric.Float64Histogram
	mOpenConns             metric.Int64UpDownCounter
	mOpenConnectionCount   metric.Int64Counter
}

// DatabaseEngine returns the configured database engine type for this recorder.
func (m *metricRecorder) DatabaseEngine() string {
	return m.dbEngineType
}

// Shutdown flushes buffered metrics and stops the periodic export. Shutting
// down the provider is sufficient: the provider shuts down its reader, and
// the reader performs a final export. The shared MetricClient is not closed
// here (see sharedClientExporter); the Dialer owns and closes it.
func (m *metricRecorder) Shutdown(ctx context.Context) error {
	return m.provider.Shutdown(ctx)
}

// sharedClientExporter wraps a Cloud Monitoring exporter whose MetricClient
// is shared with other exporters. Its Shutdown does not shut down the wrapped
// exporter, because doing so would close the shared client and break every
// other recorder still using it. The periodic reader still performs its final
// collect-and-export before calling Shutdown, so no data is lost.
type sharedClientExporter struct {
	sdkmetric.Exporter
}

// Shutdown is a no-op that leaves the shared MetricClient open.
func (sharedClientExporter) Shutdown(context.Context) error { return nil }

// RecordClosedConnectionCount records totals number of closed connections.
func (m *metricRecorder) RecordClosedConnectionCount(ctx context.Context, a Attributes) {
	m.mClosedConnectionCount.Add(ctx, 1,
		metric.WithAttributeSet(attribute.NewSet(
			attribute.String(authType, AuthTypeValue(a.IAMAuthN)),
			attribute.String(ipType, IPTypeValue(a.IPType)),
			attribute.String(status, a.DialStatus)),
		))
}

// RecordOpenConnection records current number of open connections.
func (m *metricRecorder) RecordOpenConnection(ctx context.Context, a Attributes) {
	m.mOpenConns.Add(ctx, 1,
		metric.WithAttributeSet(attribute.NewSet(
			attribute.String(authType, AuthTypeValue(a.IAMAuthN)),
			attribute.String(ipType, IPTypeValue(a.IPType)),
		)))
}

// RecordClosedConnection decreases current number of open connections.
func (m *metricRecorder) RecordClosedConnection(ctx context.Context, a Attributes) {
	m.mOpenConns.Add(ctx, -1,
		metric.WithAttributeSet(attribute.NewSet(
			attribute.String(authType, AuthTypeValue(a.IAMAuthN)),
			attribute.String(ipType, IPTypeValue(a.IPType)),
		)))
}

// RecordConnectLatencies records dial latencies.
func (m *metricRecorder) RecordConnectLatencies(ctx context.Context, a Attributes, latencyMS int64) {
	m.mConnectLatency.Record(ctx, float64(latencyMS),
		metric.WithAttributeSet(attribute.NewSet(
			attribute.String(authType, AuthTypeValue(a.IAMAuthN)),
			attribute.String(ipType, IPTypeValue(a.IPType)),
		)),
	)
}

// RecordConnectionDuration records established connection duration in seconds.
func (m *metricRecorder) RecordConnectionDuration(ctx context.Context, a Attributes, durationSec float64) {
	m.mConnectionDuration.Record(ctx, durationSec,
		metric.WithAttributeSet(attribute.NewSet(
			attribute.String(authType, AuthTypeValue(a.IAMAuthN)),
			attribute.String(ipType, IPTypeValue(a.IPType)),
		)),
	)
}

// RecordOpenConnectionCount records connection attempts and error classifications.
func (m *metricRecorder) RecordOpenConnectionCount(ctx context.Context, a Attributes) {
	m.mOpenConnectionCount.Add(ctx, 1,
		metric.WithAttributeSet(attribute.NewSet(
			attribute.String(authType, AuthTypeValue(a.IAMAuthN)),
			attribute.String(ipType, IPTypeValue(a.IPType)),
			attribute.String(connectionPart, a.ConnectionPart),
			attribute.String(status, a.AttemptStatus),
		)),
	)
}

// NullMetricRecorder implements the MetricRecorder interface with no-ops. It
// is useful for disabling the built-in metrics.
type NullMetricRecorder struct{}

// RecordOpenConnection is a no-op.
func (n NullMetricRecorder) RecordOpenConnection(context.Context, Attributes) {}

// RecordClosedConnection is a no-op.
func (n NullMetricRecorder) RecordClosedConnection(context.Context, Attributes) {}

// RecordClosedConnectionCount is a no-op.
func (n NullMetricRecorder) RecordClosedConnectionCount(context.Context, Attributes) {}

// RecordConnectLatencies is a no-op.
func (n NullMetricRecorder) RecordConnectLatencies(context.Context, Attributes, int64) {
}

// RecordConnectionDuration is a no-op.
func (n NullMetricRecorder) RecordConnectionDuration(context.Context, Attributes, float64) {
}

// RecordOpenConnectionCount is a no-op.
func (n NullMetricRecorder) RecordOpenConnectionCount(context.Context, Attributes) {}

// DatabaseEngine returns an empty string for the null recorder.
func (n NullMetricRecorder) DatabaseEngine() string {
	return ""
}

// Shutdown is a no-op.
func (n NullMetricRecorder) Shutdown(context.Context) error { return nil }
