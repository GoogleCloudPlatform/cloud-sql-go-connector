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
	"log"
	"math/rand/v2"
	"os"
	"strings"
	"sync"
	"sync/atomic"
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
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
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
	// PlatformAIStudio is the compute_platform value for applications
	// deployed by Google AI Studio. It cannot be auto-detected and must be
	// set explicitly by the embedding client (e.g. the Auth Proxy).
	PlatformAIStudio = "ai_studio"

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
	// Principal is the identity (e.g. service account email) the connector
	// authenticates with, when it can be determined. Used only to make
	// permission errors actionable. May be empty.
	Principal string
	// DisableHint tells the user how to turn built-in metrics off in the
	// client that embeds this connector (Go API vs. Auth Proxy flag). Used
	// only in error messages. May be empty.
	DisableHint string
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

// validComputePlatforms is the closed set of values allowed for the
// compute_platform label. Keeping this set small bounds the cardinality of the
// InstanceClient monitored resource.
var validComputePlatforms = map[string]bool{
	PlatformGKE:            true,
	PlatformCloudRun:       true,
	PlatformAppEngine:      true,
	PlatformCloudFunctions: true,
	PlatformGCE:            true,
	PlatformAIStudio:       true,
	UnknownValue:           true,
}

// IsValidComputePlatform reports whether p is an allowed compute_platform
// label value.
func IsValidComputePlatform(p string) bool {
	return validComputePlatforms[p]
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

// Attributes holds the per-attempt metadata attached to a metric. Every
// field here is emitted as a metric label by at least one Record method.
type Attributes struct {
	// IAMAuthN specifies whether IAM authentication is enabled (auth_type).
	IAMAuthN bool
	// DialStatus specifies the result of the dial attempt (status on
	// closed_connection_count), one of [success, error].
	DialStatus string
	// IPType is the connection type requested or, once known, the IP type
	// actually used (instance_ip_type), one of [public, private, psc,
	// sql_data, auto, unknown].
	IPType string
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

// Histogram bucket boundaries. The OpenTelemetry defaults (0, 5, 10, 25, ...,
// 10000) are tuned for request latencies in milliseconds; for connection
// durations in seconds they put everything under 5 s in one bucket and
// overflow at ~2.8 h, which pooled connections routinely exceed.
var (
	// ConnectLatencyBucketsMs covers sub-millisecond local dials through
	// the 30 s dial timeouts commonly configured by drivers.
	ConnectLatencyBucketsMs = []float64{
		1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000, 30000,
	}
	// ConnectionDurationBucketsS covers one-shot connections (sub-second)
	// through pooled connections held for up to a day.
	ConnectionDurationBucketsS = []float64{
		0.1, 0.5, 1, 5, 10, 30, 60, 300, 600, 1800, 3600, 14400, 43200, 86400,
	}
)

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
	// sharedClientExporter delegates to the real exporter but (1) makes
	// Shutdown a no-op so the shared client stays open until the Dialer
	// closes it, and (2) never surfaces export errors to the OpenTelemetry
	// global error handler, which would otherwise print to stderr on every
	// failed export. See the type documentation for details.
	sharedExp := &sharedClientExporter{
		Exporter:    exp,
		logger:      l,
		name:        cfg.ResourceID,
		project:     cfg.ResourceContainer,
		principal:   cfg.Principal,
		disableHint: cfg.DisableHint,
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
			sharedExp,
			// The periodic reader runs every 60 seconds by default, but set
			// the value anyway to be defensive.
			sdkmetric.WithInterval(DefaultExportInterval),
		)),
		sdkmetric.WithResource(res),
	)
	m := p.Meter(meterName, metric.WithInstrumentationVersion(cfg.Version))

	mConnectLatency, err := m.Float64Histogram(connectLatency,
		metric.WithUnit("ms"),
		metric.WithExplicitBucketBoundaries(ConnectLatencyBucketsMs...))
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
	mConnectionDuration, err := m.Float64Histogram(connectionDurations,
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(ConnectionDurationBucketsS...))
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
		logger:                 l,
		name:                   cfg.ResourceID,
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
	exporter     sdkmetric.Exporter
	provider     *sdkmetric.MeterProvider
	logger       debug.ContextLogger
	name         string
	dialerID     string
	dbEngineType string
	// panicLogged ensures a recovered panic is debug-logged once per
	// recorder rather than on every dial.
	panicLogged            atomic.Bool
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

// RecoveredPanics counts panics recovered on the metrics record path across
// the process. It is exported for tests and diagnostics; a non-zero value
// indicates a bug in the metrics pipeline that should be reported.
var RecoveredPanics atomic.Int64

// panicWarnOnce guards the single process-wide standard-logger line about a
// recovered panic, mirroring the permanent-export-error warning.
var panicWarnOnce sync.Once

// recoverPanic is deferred by every Record* method so that a panic inside the
// metrics SDK can never propagate into the dial path. Built-in metrics must
// not be able to break connectivity under any circumstances; the measurement
// is dropped. The panic is not hidden, though: it is counted, debug-logged
// once per recorder, and reported once per process on the standard logger so
// that the bug gets noticed and fixed.
func (m *metricRecorder) recoverPanic(ctx context.Context, op string) {
	r := recover()
	if r == nil {
		return
	}
	RecoveredPanics.Add(1)
	if m.panicLogged.CompareAndSwap(false, true) && m.logger != nil {
		m.logger.Debugf(ctx, "[%v] built-in metrics: recovered panic in %s (measurement dropped; further panics for this instance are not logged): %v", m.name, op, r)
	}
	panicWarnOnce.Do(func() {
		warnLogger.Printf("cloudsqlconn: built-in metrics recovered a panic in %s and dropped the measurement; "+
			"connectivity is unaffected. This is a bug in the connector's metrics pipeline, please report it at "+
			"https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues: %v", op, r)
	})
}

// Shutdown flushes buffered metrics and stops the periodic export. Shutting
// down the provider is sufficient: the provider shuts down its reader, and
// the reader performs a final export. The shared MetricClient is not closed
// here (see sharedClientExporter); the Dialer owns and closes it.
func (m *metricRecorder) Shutdown(ctx context.Context) error {
	return m.provider.Shutdown(ctx)
}

// Backoff applied after a failed export. Export is suspended after a failure
// and the suspension doubles on each consecutive failure up to a cap; a
// successful export resets it. There are two tiers:
//
//   - Permanent errors (missing IAM permission, invalid credentials, disabled
//     API, deleted project) will not resolve on their own, so they back off
//     from PermanentExportErrorInitialBackoff up to
//     PermanentExportErrorMaxBackoff. A client missing
//     roles/monitoring.metricWriter settles at one attempt per hour while an
//     IAM fix is still picked up within an hour without a restart.
//   - Transient errors (Monitoring API unavailable, timeouts, quota) usually
//     clear on their own, so they back off from
//     TransientExportErrorInitialBackoff up to TransientExportErrorMaxBackoff.
//     This sheds load from the Monitoring API during an outage (a fleet of
//     connectors retrying at full rate would otherwise hold it at 100% of
//     normal load while it recovers) while bounding the gap in a customer's
//     dashboard after recovery to roughly the max backoff.
//
// A small jitter is applied to every suspension so that clients that failed
// together do not all retry on the same tick. Exposed as vars to facilitate
// testing.
var (
	PermanentExportErrorInitialBackoff = 10 * time.Minute
	PermanentExportErrorMaxBackoff     = time.Hour
	TransientExportErrorInitialBackoff = 2 * time.Minute
	TransientExportErrorMaxBackoff     = 16 * time.Minute
)

// backoffJitter is the fraction of a suspension by which it is randomly
// shortened or lengthened (±).
const backoffJitter = 0.2

// permanentErrorOnce guards the single process-wide warning emitted on the
// first permanent export error. Built-in metrics are opt-in, so a user who
// enabled them but lacks the IAM role deserves to find out even without a
// debug logger; one line per process is the most a library should write to
// the application's log on its own.
var permanentErrorOnce = new(sync.Once)

// warnLogger is the destination for that single warning. It is a var so tests
// can capture it; the default is the standard library logger (stderr).
var warnLogger = log.Default()

// sharedClientExporter wraps the Cloud Monitoring exporter to make built-in
// metrics strictly fail-open and quiet:
//
//   - Shutdown is a no-op. The wrapped exporter's Shutdown closes the
//     MetricClient it was given, but that client is shared by every recorder
//     of a Dialer, so shutting down one recorder must not close it. The
//     periodic reader still performs its final collect-and-export before
//     calling Shutdown, so flushing works; the Dialer closes the client once.
//   - Export never returns an error. Errors returned to the periodic reader
//     are passed to the OpenTelemetry global error handler, whose default
//     prints to stderr on every failed export (once a minute, forever, for a
//     user who is merely missing an IAM role). Instead, errors are reported
//     through the connector's debug logger, which is a no-op unless the
//     caller opted into debug logging.
//   - Identical consecutive errors are logged once, and recovery is logged
//     once, so a persistent misconfiguration produces two lines, not one per
//     export interval.
//   - Every failure suspends export with exponential, jittered backoff: a
//     short schedule for transient errors (so a Monitoring API outage is not
//     hit at full rate by the whole fleet) and a long one for permanent
//     errors (PermissionDenied, Unauthenticated, NotFound, FailedPrecondition),
//     for which a single warning is also written to the standard logger, once
//     per process, so the misconfiguration is discoverable without a debug
//     logger.
//
// Built-in metrics therefore never affect connectivity, write at most one
// line to the application's standard logger, and never flood logs.
type sharedClientExporter struct {
	sdkmetric.Exporter
	logger      debug.ContextLogger
	name        string
	project     string
	principal   string
	disableHint string

	mu             sync.Mutex
	lastErr        string
	suspendedUntil time.Time
	// backoff is the current (un-jittered) suspension length; zero until the
	// first failure, reset to zero on success.
	backoff time.Duration
	// permanent records which backoff tier backoff belongs to, so that a
	// change of error class restarts the schedule.
	permanent bool
}

// Export exports the metrics, swallowing and rate-limiting any error.
func (e *sharedClientExporter) Export(ctx context.Context, rm *metricdata.ResourceMetrics) error {
	e.mu.Lock()
	if time.Now().Before(e.suspendedUntil) {
		e.mu.Unlock()
		return nil
	}
	e.mu.Unlock()

	err := e.Exporter.Export(ctx, rm)

	e.mu.Lock()
	defer e.mu.Unlock()
	if err == nil {
		if e.lastErr != "" {
			e.logger.Debugf(ctx, "[%v] built-in metrics export recovered", e.name)
			e.lastErr = ""
		}
		e.backoff = 0
		return nil
	}
	permanent := isPermanentExportError(err)
	initial, maxBackoff := TransientExportErrorInitialBackoff, TransientExportErrorMaxBackoff
	if permanent {
		initial, maxBackoff = PermanentExportErrorInitialBackoff, PermanentExportErrorMaxBackoff
	}
	// If the error class changed (e.g. transient outage followed by a
	// permission error), start that class's schedule from its initial value
	// rather than continuing the previous class's.
	if e.permanent != permanent {
		e.backoff = 0
		e.permanent = permanent
	}
	e.backoff = nextBackoff(e.backoff, initial, maxBackoff)
	e.suspendedUntil = time.Now().Add(jitter(e.backoff))
	if permanent {
		permanentErrorOnce.Do(func() {
			warnLogger.Printf("cloudsqlconn: built-in metrics export failed for %s: %v. %s "+
				"Retries back off exponentially up to %v; further failures are reported via the debug logger only.",
				e.name, err, e.remediationHint(err), PermanentExportErrorMaxBackoff)
		})
	}
	if msg := err.Error(); msg != e.lastErr {
		e.lastErr = msg
		if permanent {
			e.logger.Debugf(ctx, "[%v] built-in metrics export failed, suspending export (backoff %v, max %v): %v. %s",
				e.name, e.backoff, maxBackoff, err, e.remediationHint(err))
		} else {
			e.logger.Debugf(ctx, "[%v] built-in metrics export failed, retrying with backoff (%v, max %v); identical errors will not be logged again: %v",
				e.name, e.backoff, maxBackoff, err)
		}
	}
	return nil
}

// nextBackoff returns the suspension to apply after a failure given the
// previous suspension: the initial backoff first, then doubling, capped.
func nextBackoff(prev, initial, maxBackoff time.Duration) time.Duration {
	if prev <= 0 {
		return min(initial, maxBackoff)
	}
	return min(2*prev, maxBackoff)
}

// jitter returns d adjusted by a random factor in [1-backoffJitter, 1+backoffJitter].
func jitter(d time.Duration) time.Duration {
	f := 1 + backoffJitter*(2*rand.Float64()-1)
	return time.Duration(float64(d) * f)
}

// remediationHint explains how to fix a permanent export error and how to
// turn built-in metrics off, naming the principal and project when known.
//
// Two distinct causes produce PermissionDenied and need different fixes:
// a missing IAM role (grant roles/monitoring.metricWriter), and an access
// token that lacks the Monitoring scope. The latter happens when the caller
// supplies a token source or credentials scoped only to sqlservice.admin
// (WithTokenSource, WithCredentials, impersonation); no IAM grant can fix
// it, so the hint must point at the scope instead.
func (e *sharedClientExporter) remediationHint(err error) string {
	who := "the identity used by the connector"
	if e.principal != "" {
		who = "principal " + e.principal
	}
	var hint string
	if isInsufficientScopeError(err) {
		hint = "To fix, include the " + MonitoringWriteScope + " (or cloud-platform) scope in the " +
			"token source or credentials passed to the connector, for " + who + "."
	} else {
		hint = "To fix, grant roles/monitoring.metricWriter on project " + e.project + " to " + who + "."
	}
	if e.disableHint != "" {
		hint += " To turn built-in metrics off, " + e.disableHint + "."
	}
	return hint
}

// MonitoringWriteScope is the OAuth scope the metric export needs.
const MonitoringWriteScope = "https://www.googleapis.com/auth/monitoring.write"

// isInsufficientScopeError reports whether err is the Monitoring API's
// rejection of an access token that lacks a suitable scope. The API returns
// PermissionDenied with an ErrorInfo reason of ACCESS_TOKEN_SCOPE_INSUFFICIENT
// and the message "Request had insufficient authentication scopes".
func isInsufficientScopeError(err error) bool {
	st, ok := grpcstatus.FromError(err)
	if !ok || st.Code() != codes.PermissionDenied {
		return false
	}
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok && info.GetReason() == "ACCESS_TOKEN_SCOPE_INSUFFICIENT" {
			return true
		}
	}
	return strings.Contains(strings.ToLower(st.Message()), "insufficient authentication scopes")
}

// Shutdown is a no-op that leaves the shared MetricClient open.
func (*sharedClientExporter) Shutdown(context.Context) error { return nil }

// isPermanentExportError reports whether err indicates a configuration
// problem that retrying every export interval will not fix. Per the
// Monitoring API error contract:
//
//   - PermissionDenied: missing roles/monitoring.metricWriter, Monitoring API
//     not enabled, billing disabled, project not visible, VPC-SC.
//   - Unauthenticated: invalid/expired credentials or wrong scopes.
//   - NotFound: project deleted or unrecognized region label.
//   - FailedPrecondition: project/billing state that blocks writes.
//
// Everything else is treated as transient and retried next interval. That
// deliberately includes InvalidArgument: it is returned for points written
// out of order or too frequently and for partial-batch failures, all of
// which resolve on the next export of these cumulative metrics, and
// ResourceExhausted, for which a once-per-minute retry is the right cadence.
func isPermanentExportError(err error) bool {
	switch grpcstatus.Code(err) {
	case codes.PermissionDenied, codes.Unauthenticated, codes.NotFound, codes.FailedPrecondition:
		return true
	}
	return false
}

// RecordClosedConnectionCount records totals number of closed connections.
func (m *metricRecorder) RecordClosedConnectionCount(ctx context.Context, a Attributes) {
	defer m.recoverPanic(ctx, "RecordClosedConnectionCount")
	m.mClosedConnectionCount.Add(ctx, 1,
		metric.WithAttributeSet(attribute.NewSet(
			attribute.String(authType, AuthTypeValue(a.IAMAuthN)),
			attribute.String(ipType, IPTypeValue(a.IPType)),
			attribute.String(status, a.DialStatus)),
		))
}

// RecordOpenConnection records current number of open connections.
func (m *metricRecorder) RecordOpenConnection(ctx context.Context, a Attributes) {
	defer m.recoverPanic(ctx, "RecordOpenConnection")
	m.mOpenConns.Add(ctx, 1,
		metric.WithAttributeSet(attribute.NewSet(
			attribute.String(authType, AuthTypeValue(a.IAMAuthN)),
			attribute.String(ipType, IPTypeValue(a.IPType)),
		)))
}

// RecordClosedConnection decreases current number of open connections.
func (m *metricRecorder) RecordClosedConnection(ctx context.Context, a Attributes) {
	defer m.recoverPanic(ctx, "RecordClosedConnection")
	m.mOpenConns.Add(ctx, -1,
		metric.WithAttributeSet(attribute.NewSet(
			attribute.String(authType, AuthTypeValue(a.IAMAuthN)),
			attribute.String(ipType, IPTypeValue(a.IPType)),
		)))
}

// RecordConnectLatencies records dial latencies.
func (m *metricRecorder) RecordConnectLatencies(ctx context.Context, a Attributes, latencyMS int64) {
	defer m.recoverPanic(ctx, "RecordConnectLatencies")
	m.mConnectLatency.Record(ctx, float64(latencyMS),
		metric.WithAttributeSet(attribute.NewSet(
			attribute.String(authType, AuthTypeValue(a.IAMAuthN)),
			attribute.String(ipType, IPTypeValue(a.IPType)),
		)),
	)
}

// RecordConnectionDuration records established connection duration in seconds.
func (m *metricRecorder) RecordConnectionDuration(ctx context.Context, a Attributes, durationSec float64) {
	defer m.recoverPanic(ctx, "RecordConnectionDuration")
	m.mConnectionDuration.Record(ctx, durationSec,
		metric.WithAttributeSet(attribute.NewSet(
			attribute.String(authType, AuthTypeValue(a.IAMAuthN)),
			attribute.String(ipType, IPTypeValue(a.IPType)),
		)),
	)
}

// RecordOpenConnectionCount records connection attempts and error classifications.
func (m *metricRecorder) RecordOpenConnectionCount(ctx context.Context, a Attributes) {
	defer m.recoverPanic(ctx, "RecordOpenConnectionCount")
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
