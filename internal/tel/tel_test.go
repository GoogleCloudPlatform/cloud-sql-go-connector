// Copyright 2026 Google LLC
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
package tel_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cloud.google.com/go/cloudsqlconn/errtype"
	"cloud.google.com/go/cloudsqlconn/internal/cloudsql"
	"cloud.google.com/go/cloudsqlconn/internal/tel"
	"github.com/google/go-cmp/cmp"
	"go.opentelemetry.io/otel"
	"golang.org/x/oauth2"
	"google.golang.org/api/option"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"

	monitoring "cloud.google.com/go/monitoring/apiv3/v2"
	monitoringpb "cloud.google.com/go/monitoring/apiv3/v2/monitoringpb"
)

const bufSize = 4 * 1024 * 1024

type nullLogger struct {
	t *testing.T
}

func (n nullLogger) Debugf(_ context.Context, format string, args ...any) {
	n.t.Helper()
	n.t.Logf(format, args...)
}

type mockServer struct {
	mu      sync.Mutex
	gotReqs []*monitoringpb.CreateTimeSeriesRequest
	// failWith, when not OK, makes CreateServiceTimeSeries return a gRPC
	// error with that code (the request is still recorded).
	failWith codes.Code
	// failStatus, when set, takes precedence over failWith and is returned
	// verbatim (lets tests attach error details).
	failStatus *grpcstatus.Status
	monitoringpb.MetricServiceServer
}

func (m *mockServer) CreateServiceTimeSeries(_ context.Context, req *monitoringpb.CreateTimeSeriesRequest) (*emptypb.Empty, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gotReqs = append(m.gotReqs, req)
	if m.failStatus != nil {
		return nil, m.failStatus.Err()
	}
	if m.failWith != codes.OK {
		return nil, grpcstatus.Error(m.failWith, "simulated failure")
	}
	return &emptypb.Empty{}, nil
}

func (m *mockServer) setFailureStatus(st *grpcstatus.Status) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failStatus = st
}

// requests returns a copy of the recorded requests.
func (m *mockServer) requests() []*monitoringpb.CreateTimeSeriesRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]*monitoringpb.CreateTimeSeriesRequest(nil), m.gotReqs...)
}

func (m *mockServer) setFailure(c codes.Code) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failWith = c
}

func (m *mockServer) requestCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.gotReqs)
}

// lockedBuffer is a goroutine-safe bytes.Buffer for capturing log output.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// recordingLogger captures debug log lines.
type recordingLogger struct {
	mu    sync.Mutex
	lines []string
}

func (r *recordingLogger) Debugf(_ context.Context, format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, fmt.Sprintf(format, args...))
}

func (r *recordingLogger) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.lines...)
}

func equalLabels(want, got map[string]string) bool {
	return cmp.Diff(want, got) == ""
}

func verifyTimeSeries(resourceName, metricType string, resourceLabels, metricLabels map[string]string, tss []*monitoringpb.TimeSeries) bool {
	for _, ts := range tss {
		equalResource := ts.GetResource().GetType() == resourceName
		equalResourceLabels := equalLabels(resourceLabels, ts.GetResource().GetLabels())
		equalMetric := ts.GetMetric().GetType() == metricType
		equalMetricLabels := equalLabels(metricLabels, ts.GetMetric().GetLabels())
		if equalResource && equalResourceLabels && equalMetric && equalMetricLabels {
			return true
		}
	}
	return false
}

func (m *mockServer) Verify(t *testing.T, wantProjectName, wantResourceType, wantMetricType string, wantResourceLabels, wantMetricLabels map[string]string) {
	t.Helper()

	// Try for at least 2s to find the expected request.
	var lastReq *monitoringpb.CreateTimeSeriesRequest
	for range 4 {
		m.mu.Lock()
		gotReqs := m.gotReqs
		m.mu.Unlock()

		for _, req := range gotReqs {
			if req.GetName() == wantProjectName && verifyTimeSeries(wantResourceType, wantMetricType, wantResourceLabels, wantMetricLabels, req.GetTimeSeries()) {
				return
			}
		}
		// Capture last request to attempt a helpful diff on failure.
		if len(gotReqs) > 0 {
			lastReq = gotReqs[len(gotReqs)-1]
		}

		time.Sleep(250 * time.Millisecond)
	}

	if lastReq == nil {
		t.Fatal("got no requests from metric exporter")
	}

	gotProjectName := lastReq.GetName()
	if gotProjectName != wantProjectName {
		t.Fatalf("got = %v, want = %v", gotProjectName, wantProjectName)
	}

	var ts *monitoringpb.TimeSeries
	if tss := lastReq.GetTimeSeries(); len(tss) > 0 {
		ts = tss[len(tss)-1]
	}
	gotResourceType := ts.GetResource().GetType()
	if gotResourceType != wantResourceType {
		t.Fatalf("got = %v, want = %v", gotResourceType, wantResourceType)
	}
	gotResourceLabels := ts.GetResource().GetLabels()
	if diff := cmp.Diff(wantResourceLabels, gotResourceLabels); diff != "" {
		t.Fatalf("unexpected diff in resource labels (-want, +got) = %v", diff)
	}
	gotMetricType := ts.GetMetric().GetType()
	if gotMetricType != wantMetricType {
		t.Fatalf("got = %v, want = %v", gotMetricType, wantMetricType)
	}
	gotMetricLabels := ts.GetMetric().GetLabels()
	if diff := cmp.Diff(wantMetricLabels, gotMetricLabels); diff != "" {
		t.Fatalf("unexpected diff in metric labels (-want, +got) = %v", diff)
	}

	t.Fatal("failed to find matching request with unknown diff")

}

func setupMockServer(t *testing.T) (*mockServer, *grpc.ClientConn, func()) {
	t.Helper()

	s := grpc.NewServer()
	mock := &mockServer{}
	monitoringpb.RegisterMetricServiceServer(s, mock)

	lis := bufconn.Listen(bufSize)
	go func() {
		_ = s.Serve(lis)
	}()

	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}

	return mock, conn, func() {
		lis.Close()
	}
}

type nullTokenSource struct{}

func (nullTokenSource) Token() (*oauth2.Token, error) {
	return nil, nil
}

func TestMetricRecorderInitialization(t *testing.T) {
	// nil metric client should return a null metric recorder
	mr := tel.NewMetricRecorder(t.Context(), nullLogger{t}, nil, tel.Config{
		Enabled:           true,
		ResourceContainer: "my-cool-project",
	})

	if _, ok := mr.(tel.NullMetricRecorder); !ok {
		t.Fatalf("got = %T, want = %T", mr, tel.NullMetricRecorder{})
	}
}

func TestMetricRecorder(t *testing.T) {
	tel.DefaultExportInterval = 100 * time.Millisecond
	t.Cleanup(func() { tel.DefaultExportInterval = 60 * time.Second })
	defaultCfg := tel.Config{
		Enabled:           true,
		Version:           "1.2.3",
		ClientUID:         "some-uid",
		ResourceContainer: "myproject",
		Region:            "some-location",
		ResourceID:        "some-instance",
		ConnectorVersion:  "1.2.3",
		ConnectorType:     "go",
	}
	wantProject := "projects/myproject"
	wantResourceType := "cloudsql.googleapis.com/InstanceClient"
	wantResourceLabels := map[string]string{
		"resource_container":   "myproject",
		"region":               "some-location",
		"resource_id":          "some-instance",
		"client_uid":           "some-uid",
		"connector_type":       "go",
		"connector_version":    "1.2.3",
		"application_name":     "",
		"client_region":        "",
		"compute_platform":     "",
		"database_engine_type": "",
	}
	mock, conn, cleanup := setupMockServer(t)
	t.Cleanup(cleanup)

	mClient, err := monitoring.NewMetricClient(t.Context(), option.WithGRPCConn(conn), option.WithTokenSource(nullTokenSource{}))
	if err != nil {
		t.Fatal(err)
	}

	tcs := []struct {
		desc               string
		cfg                tel.Config
		attrs              tel.Attributes
		action             func(context.Context, tel.MetricRecorder, tel.Attributes)
		wantProject        string
		wantResourceType   string
		wantResourceLabels map[string]string
		wantMetricType     string
		wantMetricLabels   map[string]string
	}{
		{
			desc: "connect_latencies",
			cfg:  defaultCfg,
			attrs: tel.Attributes{
				IAMAuthN: true,
				IPType:   "public",
			},
			action: func(ctx context.Context, mr tel.MetricRecorder, attrs tel.Attributes) {
				mr.RecordConnectLatencies(ctx, attrs, 1)
			},
			wantProject:        wantProject,
			wantResourceType:   wantResourceType,
			wantResourceLabels: wantResourceLabels,
			wantMetricType:     "cloudsql.googleapis.com/client/connector/connect_latencies",
			wantMetricLabels: map[string]string{
				"instance_auth_type": "iam",
				"instance_ip_type":   "public",
			},
		},
		{
			desc: "open_connections (inc)",
			cfg:  defaultCfg,
			attrs: tel.Attributes{
				IAMAuthN: false,
				IPType:   "private",
			},
			action: func(ctx context.Context, mr tel.MetricRecorder, attrs tel.Attributes) {
				mr.RecordOpenConnection(ctx, attrs)
			},
			wantProject:        wantProject,
			wantResourceType:   wantResourceType,
			wantResourceLabels: wantResourceLabels,
			wantMetricType:     "cloudsql.googleapis.com/client/connector/open_connections",
			wantMetricLabels: map[string]string{
				"instance_auth_type": "built_in",
				"instance_ip_type":   "private",
			},
		},
		{
			desc: "open_connections (dec)",
			cfg:  defaultCfg,
			attrs: tel.Attributes{
				IAMAuthN: false,
				IPType:   "private",
			},
			action: func(ctx context.Context, mr tel.MetricRecorder, attrs tel.Attributes) {
				mr.RecordClosedConnection(ctx, attrs)
			},
			wantProject:        wantProject,
			wantResourceType:   wantResourceType,
			wantResourceLabels: wantResourceLabels,
			wantMetricType:     "cloudsql.googleapis.com/client/connector/open_connections",
			wantMetricLabels: map[string]string{
				"instance_auth_type": "built_in",
				"instance_ip_type":   "private",
			},
		},
		{
			desc: "closed_connection_count",
			cfg:  defaultCfg,
			attrs: tel.Attributes{
				DialStatus: "success",
			},
			action: func(ctx context.Context, mr tel.MetricRecorder, attrs tel.Attributes) {
				mr.RecordClosedConnectionCount(ctx, attrs)
			},
			wantProject:        wantProject,
			wantResourceType:   wantResourceType,
			wantResourceLabels: wantResourceLabels,
			wantMetricType:     "cloudsql.googleapis.com/client/connector/closed_connection_count",
			wantMetricLabels: map[string]string{
				"instance_auth_type": "built_in",
				"instance_ip_type":   tel.UnknownValue,
				"status":             "success",
			},
		},
		{
			desc: "connection_durations",
			cfg:  defaultCfg,
			attrs: tel.Attributes{
				IPType:   "public",
				IAMAuthN: true,
			},
			action: func(ctx context.Context, mr tel.MetricRecorder, attrs tel.Attributes) {
				mr.RecordConnectionDuration(ctx, attrs, 12.34)
			},
			wantProject:        wantProject,
			wantResourceType:   wantResourceType,
			wantResourceLabels: wantResourceLabels,
			wantMetricType:     "cloudsql.googleapis.com/client/connector/connection_durations",
			wantMetricLabels: map[string]string{
				"instance_auth_type": "iam",
				"instance_ip_type":   "public",
			},
		},
		{
			desc: "open_connection_count",
			cfg:  defaultCfg,
			attrs: tel.Attributes{
				IPType:         "psc",
				IAMAuthN:       false,
				ConnectionPart: "client_to_proxy",
				AttemptStatus:  "user_error",
			},
			action: func(ctx context.Context, mr tel.MetricRecorder, attrs tel.Attributes) {
				mr.RecordOpenConnectionCount(ctx, attrs)
			},
			wantProject:        wantProject,
			wantResourceType:   wantResourceType,
			wantResourceLabels: wantResourceLabels,
			wantMetricType:     "cloudsql.googleapis.com/client/connector/open_connection_count",
			wantMetricLabels: map[string]string{
				"instance_auth_type": "built_in",
				"instance_ip_type":   "psc",
				"connection_part":    "client_to_proxy",
				"status":             "user_error",
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			ctx := context.Background()
			mr := tel.NewMetricRecorder(ctx, nullLogger{t}, mClient, tc.cfg)

			tc.action(ctx, mr, tc.attrs)

			mock.Verify(t, tc.wantProject, tc.wantResourceType, tc.wantMetricType, tc.wantResourceLabels, tc.wantMetricLabels)
		})
	}

}

func TestDetectDatabaseEngineType(t *testing.T) {
	tests := []struct {
		dbVersion string
		want      string
	}{
		{"MYSQL_8_0", tel.EngineMySQL},
		{"POSTGRES_15", tel.EnginePostgreSQL},
		{"SQLSERVER_2019_STANDARD", tel.EngineSQLServer},
		{"UNKNOWN_DB", tel.UnknownValue},
		{"", tel.UnknownValue},
	}
	for _, tc := range tests {
		got := tel.DetectDatabaseEngineType(tc.dbVersion)
		if got != tc.want {
			t.Errorf("DetectDatabaseEngineType(%q) = %q, want %q", tc.dbVersion, got, tc.want)
		}
	}
}

func TestDetectComputePlatform(t *testing.T) {
	t.Setenv("K_SERVICE", "my-cloud-run-svc")
	if got := tel.DetectComputePlatform(); got != tel.PlatformCloudRun {
		t.Errorf("DetectComputePlatform() = %q, want %q", got, tel.PlatformCloudRun)
	}
}

func TestClassifyDialError(t *testing.T) {
	tests := []struct {
		err        error
		wantPart   string
		wantStatus string
	}{
		{nil, "", "success"},
		{errtype.NewConfigError("invalid instance name", "proj:inst"), "client_to_proxy", "user_error"},
		{errtype.NewRefreshError("certificate expired", "proj:inst", errors.New("api failed")), "client_to_proxy", "refresh_failed_error"},
		{errors.New("something weird happened"), "unknown", "unknown_error"},
	}
	for _, tc := range tests {
		gotPart, gotStatus := tel.ClassifyDialError(tc.err)
		if gotPart != tc.wantPart || gotStatus != tc.wantStatus {
			t.Errorf("ClassifyDialError(%v) = (%q, %q), want (%q, %q)", tc.err, gotPart, gotStatus, tc.wantPart, tc.wantStatus)
		}
	}
}

// TestLabelValuesAreLowercaseSnakeCase pins the public contract for every
// enum-like label value. These values are part of the published metric
// descriptors and are consumed by customer dashboards and alerts, so changing
// any of them is a breaking change.
func TestLabelValuesAreLowercaseSnakeCase(t *testing.T) {
	want := map[string]string{
		"UnknownValue":           "unknown",
		"ConnectorTypeGo":        "go",
		"ConnectorTypeAuthProxy": "auth_proxy",
		"PlatformGKE":            "gke",
		"PlatformCloudRun":       "cloud_run",
		"PlatformAppEngine":      "app_engine",
		"PlatformCloudFunctions": "cloud_functions",
		"PlatformGCE":            "gce",
		"PlatformAIStudio":       "ai_studio",
		"EngineMySQL":            "mysql",
		"EnginePostgreSQL":       "postgresql",
		"EngineSQLServer":        "sqlserver",
		"IPTypePublic":           "public",
		"IPTypePrivate":          "private",
		"IPTypePSC":              "psc",
		"IPTypeAuto":             "auto",
		"IPTypeSQLData":          "sql_data",
		"ConnectSuccess":         "success",
		"ConnectError":           "error",
	}
	got := map[string]string{
		"UnknownValue":           tel.UnknownValue,
		"ConnectorTypeGo":        tel.ConnectorTypeGo,
		"ConnectorTypeAuthProxy": tel.ConnectorTypeAuthProxy,
		"PlatformGKE":            tel.PlatformGKE,
		"PlatformCloudRun":       tel.PlatformCloudRun,
		"PlatformAppEngine":      tel.PlatformAppEngine,
		"PlatformCloudFunctions": tel.PlatformCloudFunctions,
		"PlatformGCE":            tel.PlatformGCE,
		"PlatformAIStudio":       tel.PlatformAIStudio,
		"EngineMySQL":            tel.EngineMySQL,
		"EnginePostgreSQL":       tel.EnginePostgreSQL,
		"EngineSQLServer":        tel.EngineSQLServer,
		"IPTypePublic":           tel.IPTypePublic,
		"IPTypePrivate":          tel.IPTypePrivate,
		"IPTypePSC":              tel.IPTypePSC,
		"IPTypeAuto":             tel.IPTypeAuto,
		"IPTypeSQLData":          tel.IPTypeSQLData,
		"ConnectSuccess":         tel.ConnectSuccess,
		"ConnectError":           tel.ConnectError,
	}
	for name, w := range want {
		g, ok := got[name]
		if !ok {
			t.Errorf("%s: missing from got map (update the test)", name)
			continue
		}
		if g != w {
			t.Errorf("%s = %q, want %q", name, g, w)
		}
		for _, r := range g {
			if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '_' {
				t.Errorf("%s = %q is not lowercase snake_case", name, g)
				break
			}
		}
	}
}

func TestIPTypeValue(t *testing.T) {
	tcs := []struct {
		in   string
		want string
	}{
		{cloudsql.PublicIP, tel.IPTypePublic},
		{cloudsql.PrivateIP, tel.IPTypePrivate},
		{cloudsql.PSC, tel.IPTypePSC},
		{cloudsql.AutoIP, tel.IPTypeAuto},
		{cloudsql.SQLData, tel.IPTypeSQLData},
		{"", tel.UnknownValue},
		{"public", tel.IPTypePublic},
		{"SomethingNew", "somethingnew"},
	}
	for _, tc := range tcs {
		if got := tel.IPTypeValue(tc.in); got != tc.want {
			t.Errorf("IPTypeValue(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestConnectorTypeValue(t *testing.T) {
	tcs := []struct {
		ua   string
		want string
	}{
		{"cloud-sql-go-connector/1.25.3", tel.ConnectorTypeGo},
		{"cloud-sql-go-connector/1.25.3 cloud-sql-proxy/2.26.0", tel.ConnectorTypeAuthProxy},
		{"", tel.ConnectorTypeGo},
	}
	for _, tc := range tcs {
		if got := tel.ConnectorTypeValue(tc.ua); got != tc.want {
			t.Errorf("ConnectorTypeValue(%q) = %q, want %q", tc.ua, got, tc.want)
		}
	}
}

func TestDetectComputePlatformValues(t *testing.T) {
	tcs := []struct {
		env  string
		want string
	}{
		{"KUBERNETES_SERVICE_HOST", tel.PlatformGKE},
		{"K_SERVICE", tel.PlatformCloudRun},
		{"GAE_SERVICE", tel.PlatformAppEngine},
		{"FUNCTION_NAME", tel.PlatformCloudFunctions},
	}
	for _, tc := range tcs {
		t.Run(tc.env, func(t *testing.T) {
			for _, e := range []string{"KUBERNETES_SERVICE_HOST", "K_SERVICE", "GAE_SERVICE", "FUNCTION_NAME"} {
				t.Setenv(e, "")
			}
			t.Setenv(tc.env, "x")
			if got := tel.DetectComputePlatform(); got != tc.want {
				t.Errorf("DetectComputePlatform() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIsValidComputePlatform(t *testing.T) {
	for _, p := range []string{
		tel.PlatformGKE, tel.PlatformCloudRun, tel.PlatformAppEngine,
		tel.PlatformCloudFunctions, tel.PlatformGCE, tel.PlatformAIStudio, tel.UnknownValue,
	} {
		if !tel.IsValidComputePlatform(p) {
			t.Errorf("IsValidComputePlatform(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"", "GCE", "AI_STUDIO", "ai-studio", "aws", "cloud_run "} {
		if tel.IsValidComputePlatform(p) {
			t.Errorf("IsValidComputePlatform(%q) = true, want false", p)
		}
	}
}

// TestExportFailuresAreQuietAndBackedOff verifies the fail-open contract of
// built-in metrics: export errors never reach the OpenTelemetry global error
// handler (stderr), identical errors are logged once at debug level, permanent
// errors suspend export for a backoff period, and recovery is logged once.
func TestExportFailuresAreQuietAndBackedOff(t *testing.T) {
	oldInterval, oldInit, oldMax := tel.DefaultExportInterval, tel.PermanentExportErrorInitialBackoff, tel.PermanentExportErrorMaxBackoff
	tel.DefaultExportInterval = 20 * time.Millisecond
	tel.PermanentExportErrorInitialBackoff = 300 * time.Millisecond
	tel.PermanentExportErrorMaxBackoff = 300 * time.Millisecond
	t.Cleanup(func() {
		tel.DefaultExportInterval = oldInterval
		tel.PermanentExportErrorInitialBackoff = oldInit
		tel.PermanentExportErrorMaxBackoff = oldMax
	})

	// Any error reaching the global handler fails the test: that is the
	// stderr-flooding path we are guarding against.
	var handled atomic.Int32
	prev := otel.GetErrorHandler()
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(error) { handled.Add(1) }))
	t.Cleanup(func() { otel.SetErrorHandler(prev) })

	// Capture the once-per-process warning that goes to the standard logger.
	var warnBuf lockedBuffer
	restore := tel.SetWarnLoggerForTest(log.New(&warnBuf, "", 0))
	t.Cleanup(restore)

	mock, conn, cleanup := setupMockServer(t)
	t.Cleanup(cleanup)
	mock.setFailure(codes.PermissionDenied)

	mClient, err := monitoring.NewMetricClient(t.Context(), option.WithGRPCConn(conn), option.WithTokenSource(nullTokenSource{}))
	if err != nil {
		t.Fatal(err)
	}
	logger := &recordingLogger{}
	ctx := context.Background()
	newRecorder := func(id string) tel.MetricRecorder {
		mr := tel.NewMetricRecorder(ctx, logger, mClient, tel.Config{
			Enabled: true, Version: "1.2.3", ClientUID: "uid", ResourceContainer: "my-db-project", ResourceID: id, Region: "r",
			Principal:   "sa@my-app.iam.gserviceaccount.com",
			DisableHint: "run the proxy with --enable-builtin-metrics=false",
		})
		if _, isNull := mr.(tel.NullMetricRecorder); isNull {
			t.Fatal("expected a real recorder")
		}
		return mr
	}
	mr := newRecorder("p:i")
	// A second recorder (another instance) sharing the process: it must not
	// produce a second standard-logger warning.
	mr2 := newRecorder("p:j")
	t.Cleanup(func() { _ = mr2.Shutdown(ctx) })
	mr.RecordOpenConnectionCount(ctx, tel.Attributes{IPType: "public", AttemptStatus: tel.ConnectSuccess})
	mr2.RecordOpenConnectionCount(ctx, tel.Attributes{IPType: "public", AttemptStatus: tel.ConnectSuccess})

	// Let several export intervals elapse while the server rejects writes.
	time.Sleep(150 * time.Millisecond)
	if got := mock.requestCount(); got != 2 {
		t.Fatalf("after a PermissionDenied, exports should be suspended; server saw %d requests, want 2 (one per recorder)", got)
	}
	lines := logger.snapshot()
	if len(lines) != 2 || !strings.Contains(lines[0], "suspending export") {
		t.Fatalf("want exactly one debug line per recorder about suspension, got %q", lines)
	}
	w := warnBuf.String()
	if strings.Count(w, "cloudsqlconn: built-in metrics export failed") != 1 {
		t.Fatalf("want exactly one standard-logger warning per process (two recorders, many intervals), got %q", w)
	}
	// Both the debug line and the warning must be actionable: role, project,
	// principal, and how to turn metrics off.
	for _, msg := range []string{lines[0], w} {
		for _, want := range []string{
			"roles/monitoring.metricWriter",
			"project my-db-project",
			"principal sa@my-app.iam.gserviceaccount.com",
			"run the proxy with --enable-builtin-metrics=false",
		} {
			if !strings.Contains(msg, want) {
				t.Errorf("message missing %q: %q", want, msg)
			}
		}
	}
	logger.lines = nil // keep the rest of the test focused on recorder 1
	_ = mr2.Shutdown(ctx)

	// Fix the "permission" and wait past the backoff: export resumes and
	// recovery is logged exactly once.
	mock.setFailure(codes.OK)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && mock.requestCount() < 2 {
		time.Sleep(20 * time.Millisecond)
	}
	if got := mock.requestCount(); got < 2 {
		t.Fatalf("export did not resume after backoff; server saw %d requests", got)
	}
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) && len(logger.snapshot()) < 1 {
		time.Sleep(10 * time.Millisecond)
	}
	// Give any erroneous extra lines a chance to appear before asserting.
	time.Sleep(3 * tel.DefaultExportInterval)
	lines = logger.snapshot()
	if len(lines) != 1 || !strings.Contains(lines[0], "recovered") {
		t.Fatalf("want exactly one debug line (recovery) after the failure line, got %q", lines)
	}
	if w := warnBuf.String(); strings.Count(w, "cloudsqlconn: built-in metrics export failed") != 1 {
		t.Fatalf("recovery must not add standard-logger output; got %q", w)
	}

	if err := mr.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if n := handled.Load(); n != 0 {
		t.Fatalf("%d error(s) reached the OpenTelemetry global error handler; built-in metrics must never do that", n)
	}
}

// TestRemediationHintWithoutPrincipal verifies the message degrades
// gracefully when the principal cannot be determined.
func TestRemediationHintWithoutPrincipal(t *testing.T) {
	oldInterval, oldInit := tel.DefaultExportInterval, tel.PermanentExportErrorInitialBackoff
	tel.DefaultExportInterval = 20 * time.Millisecond
	tel.PermanentExportErrorInitialBackoff = time.Hour
	t.Cleanup(func() {
		tel.DefaultExportInterval = oldInterval
		tel.PermanentExportErrorInitialBackoff = oldInit
	})
	var warnBuf lockedBuffer
	restore := tel.SetWarnLoggerForTest(log.New(&warnBuf, "", 0))
	t.Cleanup(restore)

	mock, conn, cleanup := setupMockServer(t)
	t.Cleanup(cleanup)
	mock.setFailure(codes.PermissionDenied)
	mClient, err := monitoring.NewMetricClient(t.Context(), option.WithGRPCConn(conn), option.WithTokenSource(nullTokenSource{}))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	mr := tel.NewMetricRecorder(ctx, nullLogger{t}, mClient, tel.Config{
		Enabled: true, Version: "1.2.3", ClientUID: "uid", ResourceContainer: "proj", ResourceID: "proj:inst", Region: "r",
		DisableHint: "pass cloudsqlconn.WithBuiltInMetrics(false) to NewDialer",
	})
	mr.RecordOpenConnectionCount(ctx, tel.Attributes{IPType: "public", AttemptStatus: tel.ConnectSuccess})
	time.Sleep(100 * time.Millisecond)
	_ = mr.Shutdown(ctx)

	w := warnBuf.String()
	for _, want := range []string{"project proj", "to the identity used by the connector", "WithBuiltInMetrics(false)"} {
		if !strings.Contains(w, want) {
			t.Errorf("warning missing %q: %q", want, w)
		}
	}
	if strings.Contains(w, "principal ") {
		t.Errorf("warning must not name a principal when unknown: %q", w)
	}
}

// TestTransientExportFailuresBackOffAndAreDeduplicated verifies that a
// non-permanent error is retried with the short backoff tier (not every
// interval), is debug-logged once, and never touches the standard logger.
func TestTransientExportFailuresBackOffAndAreDeduplicated(t *testing.T) {
	oldInterval, oldInit, oldMax := tel.DefaultExportInterval, tel.TransientExportErrorInitialBackoff, tel.TransientExportErrorMaxBackoff
	tel.DefaultExportInterval = 10 * time.Millisecond
	tel.TransientExportErrorInitialBackoff = 60 * time.Millisecond
	tel.TransientExportErrorMaxBackoff = 240 * time.Millisecond
	t.Cleanup(func() {
		tel.DefaultExportInterval = oldInterval
		tel.TransientExportErrorInitialBackoff = oldInit
		tel.TransientExportErrorMaxBackoff = oldMax
	})
	var warnBuf lockedBuffer
	restore := tel.SetWarnLoggerForTest(log.New(&warnBuf, "", 0))
	t.Cleanup(restore)

	mock, conn, cleanup := setupMockServer(t)
	t.Cleanup(cleanup)
	mock.setFailure(codes.Unavailable)

	mClient, err := monitoring.NewMetricClient(t.Context(), option.WithGRPCConn(conn), option.WithTokenSource(nullTokenSource{}))
	if err != nil {
		t.Fatal(err)
	}
	logger := &recordingLogger{}
	ctx := context.Background()
	mr := tel.NewMetricRecorder(ctx, logger, mClient, tel.Config{
		Enabled: true, Version: "1.2.3", ClientUID: "uid", ResourceContainer: "p", ResourceID: "p:i", Region: "r",
	})
	mr.RecordOpenConnectionCount(ctx, tel.Attributes{IPType: "public", AttemptStatus: tel.ConnectSuccess})
	// Expected attempts with 60ms initial, doubling, 240ms cap, ±20% jitter:
	// ~0, 60, 180, 420, 660, 900 ms -> ~6 in 1s. Every-interval would be ~100.
	time.Sleep(time.Second)
	_ = mr.Shutdown(ctx)

	if got := mock.requestCount(); got < 4 || got > 9 {
		t.Fatalf("transient errors should back off (expected ~6 attempts in 1s), server saw %d", got)
	}
	if lines := logger.snapshot(); len(lines) != 1 || !strings.Contains(lines[0], "retrying with backoff") {
		t.Fatalf("want exactly one deduplicated debug line, got %q", lines)
	}
	if w := warnBuf.String(); w != "" {
		t.Fatalf("transient errors must not write to the standard logger, got %q", w)
	}
}

// TestBackoffTierSwitchRestartsSchedule verifies that moving from a transient
// error to a permanent one (or back) starts the new tier at its initial value
// instead of continuing the previous tier's doubled value.
func TestBackoffTierSwitchRestartsSchedule(t *testing.T) {
	oldInterval := tel.DefaultExportInterval
	oldTI, oldTM := tel.TransientExportErrorInitialBackoff, tel.TransientExportErrorMaxBackoff
	oldPI, oldPM := tel.PermanentExportErrorInitialBackoff, tel.PermanentExportErrorMaxBackoff
	tel.DefaultExportInterval = 10 * time.Millisecond
	tel.TransientExportErrorInitialBackoff, tel.TransientExportErrorMaxBackoff = 40*time.Millisecond, 400*time.Millisecond
	tel.PermanentExportErrorInitialBackoff, tel.PermanentExportErrorMaxBackoff = 150*time.Millisecond, time.Hour
	t.Cleanup(func() {
		tel.DefaultExportInterval = oldInterval
		tel.TransientExportErrorInitialBackoff, tel.TransientExportErrorMaxBackoff = oldTI, oldTM
		tel.PermanentExportErrorInitialBackoff, tel.PermanentExportErrorMaxBackoff = oldPI, oldPM
	})
	restore := tel.SetWarnLoggerForTest(log.New(&lockedBuffer{}, "", 0))
	t.Cleanup(restore)

	mock, conn, cleanup := setupMockServer(t)
	t.Cleanup(cleanup)
	mock.setFailure(codes.Unavailable)
	mClient, err := monitoring.NewMetricClient(t.Context(), option.WithGRPCConn(conn), option.WithTokenSource(nullTokenSource{}))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	mr := tel.NewMetricRecorder(ctx, nullLogger{t}, mClient, tel.Config{
		Enabled: true, Version: "1.2.3", ClientUID: "uid", ResourceContainer: "p", ResourceID: "p:i", Region: "r",
	})
	mr.RecordOpenConnectionCount(ctx, tel.Attributes{IPType: "public", AttemptStatus: tel.ConnectSuccess})

	// Let the transient tier climb to its 400ms cap (40, 80, 160, 320, 400).
	time.Sleep(1200 * time.Millisecond)
	// Switch to a permanent error: the next suspension must be the permanent
	// tier's *initial* 150ms, not 2x the transient cap (800ms) nor the cap.
	mock.setFailure(codes.PermissionDenied)
	// Wait for the first PermissionDenied attempt to be made.
	deadline := time.Now().Add(time.Second)
	base := mock.requestCount()
	for time.Now().Before(deadline) && mock.requestCount() == base {
		time.Sleep(5 * time.Millisecond)
	}
	afterSwitch := mock.requestCount()
	// Within ~250ms (initial 150ms + jitter + a tick) there must be a second
	// permanent attempt; if the schedule had continued from 400ms there
	// would not be.
	time.Sleep(260 * time.Millisecond)
	if n := mock.requestCount() - afterSwitch; n < 1 {
		t.Fatalf("after switching to a permanent error the schedule should restart at the permanent initial backoff; saw %d attempts in 260ms", n)
	}
	_ = mr.Shutdown(ctx)
}

// TestJitterBounds verifies the jitter stays within ±20% and NextBackoff
// doubles to the cap.
func TestJitterBounds(t *testing.T) {
	d := 10 * time.Second
	for i := 0; i < 1000; i++ {
		j := tel.Jitter(d)
		if j < 8*time.Second || j > 12*time.Second {
			t.Fatalf("jitter(%v) = %v, want within ±20%%", d, j)
		}
	}
	initial, maxB := 10*time.Minute, time.Hour
	want := []time.Duration{10 * time.Minute, 20 * time.Minute, 40 * time.Minute, time.Hour, time.Hour}
	var prev time.Duration
	for i, w := range want {
		got := tel.NextBackoff(prev, initial, maxB)
		if got != w {
			t.Fatalf("step %d: NextBackoff = %v, want %v", i, got, w)
		}
		prev = got
	}
	if got := tel.NextBackoff(0, 2*time.Hour, time.Hour); got != time.Hour {
		t.Fatalf("initial above max should be capped, got %v", got)
	}
}

// TestIsPermanentExportError pins the classification of every gRPC code the
// Monitoring API can return for a write, so a change here is deliberate.
func TestIsPermanentExportError(t *testing.T) {
	permanent := []codes.Code{codes.PermissionDenied, codes.Unauthenticated, codes.NotFound, codes.FailedPrecondition}
	transient := []codes.Code{
		codes.InvalidArgument, codes.ResourceExhausted, codes.Unavailable, codes.DeadlineExceeded,
		codes.Internal, codes.Unknown, codes.Aborted, codes.Canceled, codes.OK,
	}
	for _, c := range permanent {
		if !tel.IsPermanentExportError(grpcstatus.Error(c, "x")) {
			t.Errorf("%v: want permanent", c)
		}
	}
	for _, c := range transient {
		if tel.IsPermanentExportError(grpcstatus.Error(c, "x")) {
			t.Errorf("%v: want transient", c)
		}
	}
	// Wrapped and joined errors (as returned by the exporter) still classify.
	wrapped := fmt.Errorf("export: %w", grpcstatus.Error(codes.PermissionDenied, "x"))
	if !tel.IsPermanentExportError(wrapped) {
		t.Error("wrapped PermissionDenied: want permanent")
	}
	joined := errors.Join(nil, grpcstatus.Error(codes.NotFound, "x"))
	if !tel.IsPermanentExportError(joined) {
		t.Error("joined NotFound: want permanent")
	}
	if tel.IsPermanentExportError(errors.New("plain error")) {
		t.Error("non-gRPC error: want transient")
	}
}

// TestRecordNeverPanics verifies that a panic inside an instrument cannot
// escape the Record* methods onto the dial path, and that it is not hidden:
// counted, debug-logged once per recorder, and reported once per process.
func TestRecordNeverPanics(t *testing.T) {
	var warn lockedBuffer
	restore := tel.SetWarnLoggerForTest(log.New(&warn, "", 0))
	t.Cleanup(restore)
	tel.ResetPanicWarnOnceForTest()
	before := tel.RecoveredPanics.Load()

	logger := &recordingLogger{}
	mr := tel.NewPanickingRecorderForTest(logger)
	ctx := context.Background()
	a := tel.Attributes{IPType: "public"}
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic escaped Record*: %v", r)
			}
		}()
		mr.RecordOpenConnection(ctx, a)
		mr.RecordClosedConnection(ctx, a)
		mr.RecordClosedConnectionCount(ctx, a)
		mr.RecordConnectLatencies(ctx, a, 1)
		mr.RecordConnectionDuration(ctx, a, 1)
		mr.RecordOpenConnectionCount(ctx, a)
	}()
	if got := tel.RecoveredPanics.Load() - before; got != 6 {
		t.Errorf("RecoveredPanics delta = %d, want 6", got)
	}
	if lines := logger.snapshot(); len(lines) != 1 || !strings.Contains(lines[0], "recovered panic") {
		t.Errorf("want exactly one debug line per recorder, got %q", lines)
	}
	if w := warn.String(); strings.Count(w, "recovered a panic") != 1 || !strings.Contains(w, "issues") {
		t.Errorf("want exactly one standard-logger line with a report link, got %q", w)
	}
	// A second recorder in the same process logs to debug again but must not
	// produce a second standard-logger line.
	mr2 := tel.NewPanickingRecorderForTest(logger)
	mr2.RecordOpenConnection(ctx, a)
	if w := warn.String(); strings.Count(w, "recovered a panic") != 1 {
		t.Errorf("standard-logger panic warning must be once per process, got %q", w)
	}
}

// TestInsufficientScopeHintPointsAtScopes verifies that when the Monitoring
// API rejects the access token for lacking a scope, the once-per-process
// warning tells the user to fix the token source's scopes rather than to
// grant an IAM role (which would not help).
func TestInsufficientScopeHintPointsAtScopes(t *testing.T) {
	oldInterval := tel.DefaultExportInterval
	tel.DefaultExportInterval = 10 * time.Millisecond
	t.Cleanup(func() { tel.DefaultExportInterval = oldInterval })
	var warnBuf lockedBuffer
	restore := tel.SetWarnLoggerForTest(log.New(&warnBuf, "", 0))
	t.Cleanup(restore)

	mock, conn, cleanup := setupMockServer(t)
	t.Cleanup(cleanup)
	st, err := grpcstatus.New(codes.PermissionDenied, "Request had insufficient authentication scopes.").
		WithDetails(&errdetails.ErrorInfo{Reason: "ACCESS_TOKEN_SCOPE_INSUFFICIENT", Domain: "googleapis.com"})
	if err != nil {
		t.Fatal(err)
	}
	mock.setFailureStatus(st)
	mClient, err := monitoring.NewMetricClient(t.Context(), option.WithGRPCConn(conn), option.WithTokenSource(nullTokenSource{}))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	mr := tel.NewMetricRecorder(ctx, nullLogger{t}, mClient, tel.Config{
		Enabled: true, Version: "1.2.3", ClientUID: "uid", ResourceContainer: "proj", ResourceID: "proj:inst", Region: "r",
	})
	mr.RecordOpenConnectionCount(ctx, tel.Attributes{IPType: "public", AttemptStatus: tel.ConnectSuccess})
	time.Sleep(100 * time.Millisecond)
	_ = mr.Shutdown(ctx)

	w := warnBuf.String()
	if !strings.Contains(w, tel.MonitoringWriteScope) {
		t.Errorf("warning should name the required scope: %q", w)
	}
	if strings.Contains(w, "grant roles/monitoring.metricWriter") {
		t.Errorf("warning must not suggest an IAM grant for a scope error: %q", w)
	}
}

// TestHistogramBucketsAreExplicit verifies that the two histograms export
// with the connector's bucket boundaries rather than the OpenTelemetry
// defaults, and that a value lands in the expected bucket.
func TestHistogramBucketsAreExplicit(t *testing.T) {
	oldInterval := tel.DefaultExportInterval
	tel.DefaultExportInterval = time.Hour
	t.Cleanup(func() { tel.DefaultExportInterval = oldInterval })

	mock, conn, cleanup := setupMockServer(t)
	t.Cleanup(cleanup)
	mClient, err := monitoring.NewMetricClient(t.Context(), option.WithGRPCConn(conn), option.WithTokenSource(nullTokenSource{}))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	mr := tel.NewMetricRecorder(ctx, nullLogger{t}, mClient, tel.Config{
		Enabled: true, Version: "1.2.3", ClientUID: "uid", ResourceContainer: "proj", ResourceID: "proj:inst", Region: "r",
	})
	attrs := tel.Attributes{IPType: "public", DialStatus: tel.ConnectSuccess}
	mr.RecordConnectLatencies(ctx, attrs, 3)
	mr.RecordConnectionDuration(ctx, attrs, 0.25)
	_ = mr.Shutdown(ctx) // flushes

	want := map[string][]float64{
		"cloudsql.googleapis.com/client/connector/connect_latencies":    tel.ConnectLatencyBucketsMs,
		"cloudsql.googleapis.com/client/connector/connection_durations": tel.ConnectionDurationBucketsS,
	}
	// Bucket i holds values in (bounds[i-1], bounds[i]]; bucket 0 is
	// (-inf, bounds[0]]. sort.SearchFloat64s returns exactly that index.
	wantBucketIdx := map[string]int{
		"cloudsql.googleapis.com/client/connector/connect_latencies":    sort.SearchFloat64s(tel.ConnectLatencyBucketsMs, 3),
		"cloudsql.googleapis.com/client/connector/connection_durations": sort.SearchFloat64s(tel.ConnectionDurationBucketsS, 0.25),
	}
	seen := map[string]bool{}
	for _, req := range mock.requests() {
		for _, ts := range req.GetTimeSeries() {
			bounds, ok := want[ts.GetMetric().GetType()]
			if !ok {
				continue
			}
			seen[ts.GetMetric().GetType()] = true
			dist := ts.GetPoints()[0].GetValue().GetDistributionValue()
			got := dist.GetBucketOptions().GetExplicitBuckets().GetBounds()
			if cmp.Diff(bounds, got) != "" {
				t.Errorf("%s bounds = %v, want %v", ts.GetMetric().GetType(), got, bounds)
			}
			if idx := wantBucketIdx[ts.GetMetric().GetType()]; dist.GetBucketCounts()[idx] != 1 {
				t.Errorf("%s bucket counts = %v, want 1 at index %d", ts.GetMetric().GetType(), dist.GetBucketCounts(), idx)
			}
		}
	}
	for m := range want {
		if !seen[m] {
			t.Errorf("%s was not exported", m)
		}
	}
}

// TestRecordWithCanceledContextStillCounts pins an OpenTelemetry SDK property
// the dial path relies on: synchronous instruments do not consult ctx.Err(),
// they only use the context for exemplar trace linkage. A Dial whose context
// is canceled or timed out (which is exactly when a failure is recorded) must
// still be counted.
func TestRecordWithCanceledContextStillCounts(t *testing.T) {
	oldInterval := tel.DefaultExportInterval
	tel.DefaultExportInterval = time.Hour
	t.Cleanup(func() { tel.DefaultExportInterval = oldInterval })

	mock, conn, cleanup := setupMockServer(t)
	t.Cleanup(cleanup)
	mClient, err := monitoring.NewMetricClient(t.Context(), option.WithGRPCConn(conn), option.WithTokenSource(nullTokenSource{}))
	if err != nil {
		t.Fatal(err)
	}
	mr := tel.NewMetricRecorder(context.Background(), nullLogger{t}, mClient, tel.Config{
		Enabled: true, Version: "1.2.3", ClientUID: "uid", ResourceContainer: "proj", ResourceID: "proj:inst", Region: "r",
	})

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cancel2 := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel2()
	attrs := tel.Attributes{IPType: "public", DialStatus: tel.ConnectError, AttemptStatus: "unknown_error"}
	mr.RecordOpenConnectionCount(canceled, attrs)
	mr.RecordConnectLatencies(expired, attrs, 42)
	mr.RecordOpenConnection(canceled, attrs)
	mr.RecordClosedConnection(expired, attrs)
	mr.RecordClosedConnectionCount(canceled, attrs)
	mr.RecordConnectionDuration(expired, attrs, 1.5)
	_ = mr.Shutdown(context.Background()) // flush

	got := map[string]bool{}
	for _, req := range mock.requests() {
		for _, ts := range req.GetTimeSeries() {
			got[ts.GetMetric().GetType()] = true
		}
	}
	for _, m := range []string{
		"cloudsql.googleapis.com/client/connector/open_connection_count",
		"cloudsql.googleapis.com/client/connector/connect_latencies",
		"cloudsql.googleapis.com/client/connector/open_connections",
		"cloudsql.googleapis.com/client/connector/closed_connection_count",
		"cloudsql.googleapis.com/client/connector/connection_durations",
	} {
		if !got[m] {
			t.Errorf("%s recorded with a canceled/expired context was not exported", m)
		}
	}
}

// TestHistogramBucketShape pins the bucket layout agreed in review:
// exponentially spaced, 20 latency buckets over 1 ms..5 min and 50 duration
// buckets over 0.1 s..24 h.
func TestHistogramBucketShape(t *testing.T) {
	tcs := []struct {
		name    string
		got     []float64
		lo, hi  float64
		n       int
		samples map[int]float64 // index -> expected value (2 d.p.)
	}{
		{
			name: "connect_latencies", got: tel.ConnectLatencyBucketsMs, lo: 1, hi: 300_000, n: 20,
			samples: map[int]float64{1: 1.94, 2: 3.77, 10: 763.30, 18: 154472.69},
		},
		{
			name: "connection_durations", got: tel.ConnectionDurationBucketsS, lo: 0.1, hi: 86_400, n: 50,
			samples: map[int]float64{1: 0.13, 19: 20.04, 20: 26.49, 37: 3038.60, 48: 65367.28},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.got) != tc.n {
				t.Fatalf("len = %d, want %d", len(tc.got), tc.n)
			}
			if tc.got[0] != tc.lo || tc.got[tc.n-1] != tc.hi {
				t.Errorf("end points = %v..%v, want %v..%v", tc.got[0], tc.got[tc.n-1], tc.lo, tc.hi)
			}
			ratio := tc.got[1] / tc.got[0]
			for i := 1; i < tc.n; i++ {
				if r := tc.got[i] / tc.got[i-1]; math.Abs(r-ratio) > 1e-9 {
					t.Errorf("ratio at %d = %v, want constant %v", i, r, ratio)
				}
			}
			for i, want := range tc.samples {
				if got := math.Round(tc.got[i]*100) / 100; got != want {
					t.Errorf("bucket[%d] = %.2f, want %.2f", i, got, want)
				}
			}
		})
	}
}

// TestFinalFlushWithinMinWriteIntervalIsQuiet reproduces the Monitoring API
// rejecting a flush that arrives within the metric's minimum write interval
// of the previous export (FailedPrecondition, "written more frequently than
// the maximum sampling period"). This is expected when a process exits
// shortly after a periodic export; it must not produce the standard-logger
// warning (it is not an IAM problem) and must not suspend export.
func TestFinalFlushWithinMinWriteIntervalIsQuiet(t *testing.T) {
	oldInterval := tel.DefaultExportInterval
	tel.DefaultExportInterval = 20 * time.Millisecond
	t.Cleanup(func() { tel.DefaultExportInterval = oldInterval })
	var warnBuf lockedBuffer
	restore := tel.SetWarnLoggerForTest(log.New(&warnBuf, "", 0))
	t.Cleanup(restore)
	logger := &recordingLogger{}

	mock, conn, cleanup := setupMockServer(t)
	t.Cleanup(cleanup)
	mock.setFailureStatus(grpcstatus.New(codes.FailedPrecondition,
		"One or more TimeSeries could not be written: timeSeries[0-4] (...): write for resource failed: "+
			"One or more points were written more frequently than the maximum sampling period configured for the metric. "+
			"{Metric: 353236655391.service.cloudsql.googleapis.com/client/connector/connect_latencies, "+
			"Timestamps: {Youngest Existing: '2026/10/23-14:57:14.570', New: '2026/10/23-14:57:30.730'}}"))
	mClient, err := monitoring.NewMetricClient(t.Context(), option.WithGRPCConn(conn), option.WithTokenSource(nullTokenSource{}))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	mr := tel.NewMetricRecorder(ctx, logger, mClient, tel.Config{
		Enabled: true, Version: "1.2.3", ClientUID: "uid", ResourceContainer: "proj", ResourceID: "proj:inst", Region: "r",
	})
	mr.RecordOpenConnectionCount(ctx, tel.Attributes{IPType: "public", AttemptStatus: tel.ConnectSuccess})
	time.Sleep(70 * time.Millisecond) // a few rejected exports
	before := mock.requestCount()
	if before == 0 {
		t.Fatal("no export attempted")
	}

	if w := warnBuf.String(); w != "" {
		t.Fatalf("standard-logger warning for a min-write-interval rejection: %q", w)
	}
	var sawDebug, sawSuspend bool
	for _, l := range logger.snapshot() {
		if strings.Contains(l, "minimum write interval") {
			sawDebug = true
		}
		if strings.Contains(l, "suspending export") || strings.Contains(l, "retrying with backoff") {
			sawSuspend = true
		}
	}
	if !sawDebug {
		t.Errorf("want a debug line explaining the dropped flush, got %q", logger.snapshot())
	}
	if sawSuspend {
		t.Errorf("rejection must not suspend or back off export, got %q", logger.snapshot())
	}

	// No suspension: once the server accepts again, the very next interval
	// exports (a suspended exporter would skip for TransientExportErrorInitialBackoff).
	mock.setFailureStatus(nil)
	time.Sleep(60 * time.Millisecond)
	if after := mock.requestCount(); after <= before {
		t.Fatalf("export did not continue after the rejection: %d -> %d requests", before, after)
	}
	_ = mr.Shutdown(ctx)
}

// TestCanceledExportIsNotAFailure pins that an export interrupted by context
// cancellation (what an in-flight export sees when the reader shuts down) is
// neither logged nor counted against the backoff schedule. Before this, a
// shutdown racing a periodic export produced a second, differently-worded
// debug line and made TestTransientExportFailuresBackOffAndAreDeduplicated
// flaky.
func TestCanceledExportIsNotAFailure(t *testing.T) {
	oldInterval := tel.DefaultExportInterval
	tel.DefaultExportInterval = time.Hour
	t.Cleanup(func() { tel.DefaultExportInterval = oldInterval })
	var warnBuf lockedBuffer
	restore := tel.SetWarnLoggerForTest(log.New(&warnBuf, "", 0))
	t.Cleanup(restore)
	logger := &recordingLogger{}

	mock, conn, cleanup := setupMockServer(t)
	t.Cleanup(cleanup)
	mock.setFailure(codes.Canceled)
	mClient, err := monitoring.NewMetricClient(t.Context(), option.WithGRPCConn(conn), option.WithTokenSource(nullTokenSource{}))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	mr := tel.NewMetricRecorder(ctx, logger, mClient, tel.Config{
		Enabled: true, Version: "1.2.3", ClientUID: "uid", ResourceContainer: "p", ResourceID: "p:i", Region: "r",
	})
	mr.RecordOpenConnectionCount(ctx, tel.Attributes{IPType: "public", AttemptStatus: tel.ConnectSuccess})
	_ = mr.Shutdown(ctx) // forces one export, which the server answers with Canceled

	if got := mock.requestCount(); got != 1 {
		t.Fatalf("want 1 export attempt, got %d", got)
	}
	if lines := logger.snapshot(); len(lines) != 0 {
		t.Fatalf("a canceled export must not be logged, got %q", lines)
	}
	if w := warnBuf.String(); w != "" {
		t.Fatalf("a canceled export must not reach the standard logger, got %q", w)
	}
}

// TestRemediationHintMatchesCause verifies that the once-per-process warning
// names the actual fix for each permanent-error cause, not always the IAM
// role: a disabled Monitoring API, a universe-domain mismatch and an
// under-scoped token each need something else.
func TestRemediationHintMatchesCause(t *testing.T) {
	oldInterval := tel.DefaultExportInterval
	tel.DefaultExportInterval = 10 * time.Millisecond
	t.Cleanup(func() { tel.DefaultExportInterval = oldInterval })

	serviceDisabled, _ := grpcstatus.New(codes.PermissionDenied,
		"Cloud Monitoring API has not been used in project 64201112091 before or it is disabled.").
		WithDetails(&errdetails.ErrorInfo{Reason: "SERVICE_DISABLED", Domain: "googleapis.com",
			Metadata: map[string]string{"consumer": "projects/64201112091", "containerInfo": "64201112091", "service": "monitoring.googleapis.com"}})
	tcs := []struct {
		desc        string
		st          *grpcstatus.Status
		wantSubstr  string
		notContains string
	}{
		// The billed project (from ErrorInfo) is named, not the instance project ("proj").
		{"service disabled", serviceDisabled, "enable the Cloud Monitoring API (monitoring.googleapis.com) on project 64201112091", "on project proj"},
		{"universe mismatch", grpcstatus.New(codes.Unauthenticated, "credentials: universe domain mismatch: client example.universe, credentials googleapis.com"), "same universe domain", "grant roles/monitoring.metricWriter"},
		{"missing role", grpcstatus.New(codes.PermissionDenied, "Permission monitoring.timeSeries.create denied"), "grant roles/monitoring.metricWriter", "enable the Cloud Monitoring API"},
	}
	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			var warnBuf lockedBuffer
			restore := tel.SetWarnLoggerForTest(log.New(&warnBuf, "", 0))
			t.Cleanup(restore)
			mock, conn, cleanup := setupMockServer(t)
			t.Cleanup(cleanup)
			mock.setFailureStatus(tc.st)
			mClient, err := monitoring.NewMetricClient(t.Context(), option.WithGRPCConn(conn), option.WithTokenSource(nullTokenSource{}))
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			mr := tel.NewMetricRecorder(ctx, nullLogger{t}, mClient, tel.Config{
				Enabled: true, Version: "1.2.3", ClientUID: "uid", ResourceContainer: "proj", ResourceID: "proj:inst", Region: "r",
			})
			mr.RecordOpenConnectionCount(ctx, tel.Attributes{IPType: "public", AttemptStatus: tel.ConnectSuccess})
			time.Sleep(100 * time.Millisecond)
			_ = mr.Shutdown(ctx)
			w := warnBuf.String()
			if !strings.Contains(w, tc.wantSubstr) {
				t.Errorf("warning should contain %q, got %q", tc.wantSubstr, w)
			}
			if strings.Contains(w, tc.notContains) {
				t.Errorf("warning should not contain %q, got %q", tc.notContains, w)
			}
		})
	}
}

// TestConnectorVersionValue verifies that the connector_version label is the
// Auth Proxy's version when the connector is embedded in the proxy, and the
// connector's own version otherwise.
func TestConnectorVersionValue(t *testing.T) {
	tcs := []struct{ ua, want string }{
		{"cloud-sql-go-connector/1.26.0", "1.26.0"},
		{"cloud-sql-go-connector/1.26.0 cloud-sql-proxy/2.27.0", "2.27.0"},
		{"cloud-sql-proxy/2.27.0+dev cloud-sql-go-connector/1.26.0 my-app/3", "2.27.0+dev"},
		{"cloud-sql-go-connector/1.26.0 cloud-sql-proxy/", "1.26.0"},
		{"", "1.26.0"},
	}
	for _, tc := range tcs {
		if got := tel.ConnectorVersionValue(tc.ua, "1.26.0"); got != tc.want {
			t.Errorf("ConnectorVersionValue(%q) = %q, want %q", tc.ua, got, tc.want)
		}
	}
}

// TestPermanentErrorWarningIsOneLine verifies that the once-per-process
// warning is a single physical line even when the gRPC error carries
// multi-line details, so log collectors see one entry.
func TestPermanentErrorWarningIsOneLine(t *testing.T) {
	oldInterval := tel.DefaultExportInterval
	tel.DefaultExportInterval = 10 * time.Millisecond
	t.Cleanup(func() { tel.DefaultExportInterval = oldInterval })
	var warnBuf lockedBuffer
	restore := tel.SetWarnLoggerForTest(log.New(&warnBuf, "", 0))
	t.Cleanup(restore)

	mock, conn, cleanup := setupMockServer(t)
	t.Cleanup(cleanup)
	st, err := grpcstatus.New(codes.PermissionDenied, "Permission monitoring.timeSeries.create denied (or the resource may not exist).").
		WithDetails(&errdetails.DebugInfo{Detail: "Permission monitoring.timeSeries.create denied on projects/123: no extra explanation needed."})
	if err != nil {
		t.Fatal(err)
	}
	mock.setFailureStatus(st)
	mClient, err := monitoring.NewMetricClient(t.Context(), option.WithGRPCConn(conn), option.WithTokenSource(nullTokenSource{}))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	mr := tel.NewMetricRecorder(ctx, nullLogger{t}, mClient, tel.Config{
		Enabled: true, Version: "1.2.3", ClientUID: "uid", ResourceContainer: "proj", ResourceID: "proj:inst", Region: "r",
	})
	mr.RecordOpenConnectionCount(ctx, tel.Attributes{IPType: "public", AttemptStatus: tel.ConnectSuccess})
	time.Sleep(100 * time.Millisecond)
	_ = mr.Shutdown(ctx)

	w := strings.TrimRight(warnBuf.String(), "\n")
	if w == "" {
		t.Fatal("expected a warning")
	}
	if n := strings.Count(w, "\n"); n != 0 {
		t.Fatalf("warning spans %d extra line(s): %q", n, w)
	}
	if !strings.Contains(w, "DebugInfo") || !strings.Contains(w, "grant roles/monitoring.metricWriter") {
		t.Fatalf("warning lost content: %q", w)
	}
}
