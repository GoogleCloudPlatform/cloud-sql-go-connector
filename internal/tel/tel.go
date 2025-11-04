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

import (
	"context"
	"strings"
	"time"

	"cloud.google.com/go/cloudsqlconn/debug"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	"google.golang.org/api/option"

	cmexporter "github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

const (
	meterName             = "cloudsql.googleapis.com/client/connector"
	monitoredResource     = "cloudsql.googleapis.com/InstanceClient"
	connectLatency        = "connect_latencies" // dial latency
	closedConnectionCount = "closed_connection_count"
	openConnections       = "open_connections"

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
)

// Config holds all the necessary information to configure a MetricRecorder.
type Config struct {
	// Enabled specifies whether the metrics should be enabled.
	Enabled bool
	// Version is the version of the alloydbconn.Dialer.
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
		return "cloud-sql-proxy"
	}
	return "go"
}

// AuthTypeValue returns the auth type string based on whether IAM Authn is enabled.
func AuthTypeValue(iamAuthn bool) string {
	if iamAuthn {
		return "iam"
	}
	return "built_in"
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
}

// MetricRecorder defines the interface for recording metrics related to the
// internal operations of alloydbconn.Dialer.
type MetricRecorder interface {
	RecordOpenConnection(context.Context, Attributes)
	RecordClosedConnection(context.Context, Attributes)
	RecordClosedConnectionCount(context.Context, Attributes)
	RecordConnectLatencies(context.Context, Attributes, int64)
}

// DefaultExportInterval is the interval that the metric exporter runs. It
// should always be 60s. This value is exposed as a var to faciliate testing.
var DefaultExportInterval = 60 * time.Second

// NewMetricRecorder creates a MetricRecorder. When the configuration is not
// enabled, a null recorder is returned instead.
func NewMetricRecorder(ctx context.Context, l debug.ContextLogger, cfg Config, opts ...option.ClientOption) MetricRecorder {
	if !cfg.Enabled {
		l.Debugf(ctx, "disabling built-in metrics")
		return NullMetricRecorder{}
	}

	eopts := []cmexporter.Option{
		cmexporter.WithCreateServiceTimeSeries(),
		cmexporter.WithProjectID(cfg.ResourceContainer),
		cmexporter.WithMonitoringClientOptions(opts...),
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
			exp,
			// The periodic reader runs every 60 seconds by default, but set
			// the value anyway to be defensive.
			sdkmetric.WithInterval(DefaultExportInterval),
		)),
		sdkmetric.WithResource(res),
	)
	m := p.Meter(meterName, metric.WithInstrumentationVersion(cfg.Version))

	mConnectLatency, err := m.Float64Histogram(connectLatency)
	if err != nil {
		_ = exp.Shutdown(ctx)
		l.Debugf(ctx, "built-in metrics exporter failed to initialize dial latency metric: %v", err)
		return NullMetricRecorder{}
	}
	mOpenConns, err := m.Int64UpDownCounter(openConnections)
	if err != nil {
		_ = exp.Shutdown(ctx)
		l.Debugf(ctx, "built-in metrics exporter failed to initialize open connections metric: %v", err)
		return NullMetricRecorder{}
	}
	mClosedConnectionCount, err := m.Int64Counter(closedConnectionCount)
	if err != nil {
		_ = exp.Shutdown(ctx)
		l.Debugf(ctx, "built-in metrics exporter failed to initialize refresh count metric: %v", err)
		return NullMetricRecorder{}
	}
	return &metricRecorder{
		exporter:               exp,
		provider:               p,
		dialerID:               cfg.ClientUID,
		mClosedConnectionCount: mClosedConnectionCount,
		mConnectLatency:        mConnectLatency,
		mOpenConns:             mOpenConns,
	}
}

// metricRecorder holds the various counters that track internal operations.
type metricRecorder struct {
	exporter               sdkmetric.Exporter
	provider               *sdkmetric.MeterProvider
	dialerID               string
	mClosedConnectionCount metric.Int64Counter
	mConnectLatency        metric.Float64Histogram
	mOpenConns             metric.Int64UpDownCounter
}

// RecordClosedConnectionCount records totals number of closed connections.
func (m *metricRecorder) RecordClosedConnectionCount(ctx context.Context, a Attributes) {
	m.mClosedConnectionCount.Add(ctx, 1,
		metric.WithAttributeSet(attribute.NewSet(
			attribute.String(authType, AuthTypeValue(a.IAMAuthN)),
			attribute.String(ipType, a.IPType),
			attribute.String(status, a.DialStatus)),
		))
}

// RecordOpenConnection records current number of open connections.
func (m *metricRecorder) RecordOpenConnection(ctx context.Context, a Attributes) {
	m.mOpenConns.Add(ctx, 1,
		metric.WithAttributeSet(attribute.NewSet(
			attribute.String(authType, AuthTypeValue(a.IAMAuthN)),
			attribute.String(ipType, a.IPType),
		)))
}

// RecordOpenConnection records current number of open connections.
func (m *metricRecorder) RecordClosedConnection(ctx context.Context, a Attributes) {
	m.mOpenConns.Add(ctx, -1,
		metric.WithAttributeSet(attribute.NewSet(
			attribute.String(authType, AuthTypeValue(a.IAMAuthN)),
			attribute.String(ipType, a.IPType),
		)))
}

// RecordConnectLatencies records dial latencies.
func (m *metricRecorder) RecordConnectLatencies(ctx context.Context, a Attributes, latencyMS int64) {
	m.mConnectLatency.Record(ctx, float64(latencyMS),
		metric.WithAttributeSet(attribute.NewSet(
			attribute.String(authType, AuthTypeValue(a.IAMAuthN)),
			attribute.String(ipType, a.IPType),
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
