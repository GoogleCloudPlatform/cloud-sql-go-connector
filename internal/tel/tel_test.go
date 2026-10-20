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
	"net"
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
	monitoringpb.MetricServiceServer
}

func (m *mockServer) CreateServiceTimeSeries(_ context.Context, req *monitoringpb.CreateTimeSeriesRequest) (*emptypb.Empty, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gotReqs = append(m.gotReqs, req)
	if m.failWith != codes.OK {
		return nil, grpcstatus.Error(m.failWith, "simulated failure")
	}
	return &emptypb.Empty{}, nil
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
		"RefreshAheadType":       "refresh_ahead",
		"RefreshLazyType":        "lazy",
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
		"RefreshAheadType":       tel.RefreshAheadType,
		"RefreshLazyType":        tel.RefreshLazyType,
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
	oldInterval, oldBackoff := tel.DefaultExportInterval, tel.PermanentExportErrorBackoff
	tel.DefaultExportInterval = 20 * time.Millisecond
	tel.PermanentExportErrorBackoff = 300 * time.Millisecond
	t.Cleanup(func() {
		tel.DefaultExportInterval = oldInterval
		tel.PermanentExportErrorBackoff = oldBackoff
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
			DisableHint: "remove the --enable-builtin-metrics flag",
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
			"remove the --enable-builtin-metrics flag",
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
	oldInterval, oldBackoff := tel.DefaultExportInterval, tel.PermanentExportErrorBackoff
	tel.DefaultExportInterval = 20 * time.Millisecond
	tel.PermanentExportErrorBackoff = time.Hour
	t.Cleanup(func() {
		tel.DefaultExportInterval = oldInterval
		tel.PermanentExportErrorBackoff = oldBackoff
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

// TestTransientExportFailuresAreDeduplicated verifies that a non-permanent
// error (which is retried every interval) is logged once, not once per
// interval.
func TestTransientExportFailuresAreDeduplicated(t *testing.T) {
	oldInterval := tel.DefaultExportInterval
	tel.DefaultExportInterval = 20 * time.Millisecond
	t.Cleanup(func() { tel.DefaultExportInterval = oldInterval })

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
	time.Sleep(150 * time.Millisecond)
	_ = mr.Shutdown(ctx)

	if got := mock.requestCount(); got < 3 {
		t.Fatalf("transient errors should keep retrying every interval; server saw only %d requests", got)
	}
	if lines := logger.snapshot(); len(lines) != 1 || !strings.Contains(lines[0], "will not be logged again") {
		t.Fatalf("want exactly one deduplicated debug line, got %q", lines)
	}
	if w := warnBuf.String(); w != "" {
		t.Fatalf("transient errors must not write to the standard logger, got %q", w)
	}
}
