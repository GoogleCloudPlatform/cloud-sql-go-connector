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

package cloudsqlconn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/cloudsqlconn/errtype"
	"cloud.google.com/go/cloudsqlconn/instance"
	"cloud.google.com/go/cloudsqlconn/internal/mock"
	"cloud.google.com/go/cloudsqlconn/internal/tel"
	sqlpb "cloud.google.com/go/sql/apiv1beta4/sqlpb"
	"go.opencensus.io/stats/view"
	"google.golang.org/api/option"
)

// countingRecorder is a tel.MetricRecorder that remembers every call, so
// tests can assert what the dial path records without a metrics backend.
type countingRecorder struct {
	// engine is what DatabaseEngine reports. The dial path replaces a
	// recorder whose engine differs from the instance's, so tests on the
	// direct-IP path set it to the fake instance's engine.
	engine        string
	mu            sync.Mutex
	open          int // RecordOpenConnection minus RecordClosedConnection
	openCount     []tel.Attributes
	closedCount   []tel.Attributes
	latencies     []int64
	durations     []float64
	latencyAttrs  []tel.Attributes
	durationAttrs []tel.Attributes
}

func (c *countingRecorder) RecordOpenConnection(_ context.Context, _ tel.Attributes) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.open++
}

func (c *countingRecorder) RecordClosedConnection(_ context.Context, _ tel.Attributes) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.open--
}

func (c *countingRecorder) RecordClosedConnectionCount(_ context.Context, a tel.Attributes) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closedCount = append(c.closedCount, a)
}

func (c *countingRecorder) RecordConnectLatencies(_ context.Context, a tel.Attributes, ms int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.latencies = append(c.latencies, ms)
	c.latencyAttrs = append(c.latencyAttrs, a)
}

func (c *countingRecorder) RecordConnectionDuration(_ context.Context, a tel.Attributes, s float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.durations = append(c.durations, s)
	c.durationAttrs = append(c.durationAttrs, a)
}

func (c *countingRecorder) RecordOpenConnectionCount(_ context.Context, a tel.Attributes) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.openCount = append(c.openCount, a)
}

func (c *countingRecorder) DatabaseEngine() string {
	if c.engine == "" {
		return tel.UnknownValue
	}
	return c.engine
}

func (c *countingRecorder) Shutdown(context.Context) error { return nil }

// installRecorder makes d use rec for every dial to cn. The dial path only
// replaces a recorder when it learns a database engine, which the SQL Data
// path never does, so rec stays in place for the whole test.
func installRecorder(t *testing.T, d *Dialer, icn string, rec tel.MetricRecorder) {
	t.Helper()
	cn, err := instance.ParseConnName(icn)
	if err != nil {
		t.Fatal(err)
	}
	d.metricsMu.Lock()
	d.metricRecorders[newMetricRecorderKey(cn)] = rec
	d.metricsMu.Unlock()
}

func echoHandler(stream sqlpb.SqlDataService_StreamSqlDataServer) error {
	if _, err := stream.Recv(); err != nil {
		return err
	}
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if data := req.GetData(); data != nil {
			err := stream.Send(&sqlpb.StreamSqlDataResponse{
				Message: &sqlpb.StreamSqlDataResponse_Data{
					Data: &sqlpb.DataPacket{Data: data.GetData()},
				},
			})
			if err != nil {
				return err
			}
		}
	}
}

// TestSQLDataPathRecordsMetrics verifies that a connection through the SQL
// Data service is counted like any other: one successful attempt and one
// open connection labelled sql_data, and one close with a duration.
func TestSQLDataPathRecordsMetrics(t *testing.T) {
	addr, cleanup := startMockServer(t, echoHandler)
	defer cleanup()

	ctx := context.Background()
	d, err := newTestDialer(ctx, addr, 45*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	rec := &countingRecorder{}
	installRecorder(t, d, "proj:reg:inst", rec)

	conn, err := d.Dial(ctx, "proj:reg:inst", WithSQLData())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := conn.Read(buf); err != nil {
		t.Fatal(err)
	}

	rec.mu.Lock()
	if rec.open != 1 {
		t.Errorf("open connections after dial = %d, want 1", rec.open)
	}
	if len(rec.openCount) != 1 || len(rec.latencies) != 1 {
		t.Fatalf("want 1 attempt and 1 latency sample, got %d and %d", len(rec.openCount), len(rec.latencies))
	}
	a := rec.openCount[0]
	rec.mu.Unlock()
	if got := tel.IPTypeValue(a.IPType); got != tel.IPTypeSQLData {
		t.Errorf("instance_ip_type = %q, want %q", got, tel.IPTypeSQLData)
	}
	if a.AttemptStatus != tel.ConnectSuccess || a.DialStatus != tel.ConnectSuccess {
		t.Errorf("status = %q/%q, want success", a.AttemptStatus, a.DialStatus)
	}

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close() // second close must not double count

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.open != 0 {
		t.Errorf("open connections after close = %d, want 0", rec.open)
	}
	if len(rec.closedCount) != 1 || len(rec.durations) != 1 {
		t.Errorf("want 1 closed count and 1 duration, got %d and %d", len(rec.closedCount), len(rec.durations))
	}
}

// TestSQLDataPathRecordsFailures verifies that a SQL Data dial that fails
// (here: the endpoint refuses connections) is recorded as a failed attempt
// labelled sql_data, and never as an open connection.
func TestSQLDataPathRecordsFailures(t *testing.T) {
	// Reserve a port and release it so that nothing listens there.
	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := lis.Addr().String()
	_ = lis.Close()

	ctx := context.Background()
	d, err := newTestDialer(ctx, addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	rec := &countingRecorder{}
	installRecorder(t, d, "proj:reg:inst", rec)

	if _, err := d.Dial(ctx, "proj:reg:inst", WithSQLData()); err == nil {
		t.Fatal("expected Dial to fail")
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.open != 0 {
		t.Errorf("open connections = %d, want 0", rec.open)
	}
	if len(rec.openCount) != 1 || len(rec.latencies) != 1 {
		t.Fatalf("want 1 attempt and 1 latency sample, got %d and %d", len(rec.openCount), len(rec.latencies))
	}
	if a := rec.openCount[0]; a.DialStatus != tel.ConnectError || tel.IPTypeValue(a.IPType) != tel.IPTypeSQLData {
		t.Errorf("attempt = %+v, want error status with sql_data ip type", a)
	}
}

// TestSQLDataCooldownRecordsFailure verifies that a dial refused by the
// resource-exhausted cooldown is recorded as a failed attempt.
func TestSQLDataCooldownRecordsFailure(t *testing.T) {
	ctx := context.Background()
	d, err := NewDialer(ctx, WithTokenSource(mock.EmptyTokenSource{}))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	rec := &countingRecorder{}
	installRecorder(t, d, "proj:reg:inst", rec)
	cn, _ := instance.ParseConnName("proj:reg:inst")
	d.sqlDataConnState[createKey(cn)] = &sqlDataConnState{
		allowed:       true,
		cooldownUntil: time.Now().Add(time.Hour),
		lastErr:       errors.New("resource busy"),
	}

	_, err = d.Dial(ctx, "proj:reg:inst", WithSQLData())
	var reErr *errtype.ResourceExhaustedError
	if !errors.As(err, &reErr) {
		t.Fatalf("want ResourceExhaustedError, got %v", err)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.openCount) != 1 || rec.openCount[0].DialStatus != tel.ConnectError {
		t.Errorf("want 1 failed attempt, got %+v", rec.openCount)
	}
}

// TestInstrumentedConnCloseIsIdempotent verifies that closing a direct-IP
// connection twice reports the close once.
func TestInstrumentedConnCloseIsIdempotent(t *testing.T) {
	inst := mock.NewFakeCSQLInstance("my-project", "my-region", "my-instance")
	d := setupDialer(t, setupConfig{
		testInstance: inst,
		reqs: []*mock.Request{
			mock.InstanceGetSuccess(inst, 1),
			mock.CreateEphemeralSuccess(inst, 1),
		},
	})
	rec := &countingRecorder{engine: tel.EnginePostgreSQL}
	installRecorder(t, d, "my-project:my-region:my-instance", rec)

	conn, err := d.Dial(context.Background(), "my-project:my-region:my-instance")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	_ = conn.Close()

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.open != 0 {
		t.Errorf("open connections = %d, want 0 (close counted twice?)", rec.open)
	}
	if len(rec.closedCount) != 1 || len(rec.durations) != 1 {
		t.Errorf("want 1 closed count and 1 duration, got %d and %d", len(rec.closedCount), len(rec.durations))
	}
}

// TestResolveFailureIsRecordedAsDialFailure verifies that a failure to
// resolve the instance name is still reported on the pre-existing
// OpenCensus dial_failure_count metric, i.e. the span starts before
// resolution.
func TestResolveFailureIsRecordedAsDialFailure(t *testing.T) {
	spy := &spyMetricsExporter{}
	view.RegisterExporter(spy)
	defer view.UnregisterExporter(spy)
	view.SetReportingPeriod(time.Millisecond)

	d, err := NewDialer(context.Background(), WithTokenSource(mock.EmptyTokenSource{}))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	if _, err := d.Dial(context.Background(), "not-a-valid-name"); err == nil {
		t.Fatal("expected Dial to fail on an unresolvable name")
	}
	time.Sleep(10 * time.Millisecond) // allow exporter a chance to run
	wantCountMetric(t, "cloudsqlconn/dial_failure_count", spy.data())
}

// slowRecorder is a countingRecorder whose Shutdown takes a fixed time and
// records when it finished, to observe where shutdowns run relative to the
// dial path and to Close.
type slowRecorder struct {
	countingRecorder
	delay    time.Duration
	shutDown chan struct{}
}

func newSlowRecorder(engine string, delay time.Duration) *slowRecorder {
	return &slowRecorder{
		countingRecorder: countingRecorder{engine: engine},
		delay:            delay,
		shutDown:         make(chan struct{}),
	}
}

func (s *slowRecorder) Shutdown(context.Context) error {
	time.Sleep(s.delay)
	close(s.shutDown)
	return nil
}

// TestReplacedRecorderShutsDownOffTheDialPath verifies that replacing the
// engine-unknown recorder returns immediately rather than waiting for the old
// recorder's flush, and that Close still waits for that flush before
// returning.
func TestReplacedRecorderShutsDownOffTheDialPath(t *testing.T) {
	ctx := context.Background()
	d, err := NewDialer(ctx, WithTokenSource(mock.EmptyTokenSource{}))
	if err != nil {
		t.Fatal(err)
	}
	const delay = 300 * time.Millisecond
	old := newSlowRecorder(tel.UnknownValue, delay)
	installRecorder(t, d, "proj:reg:inst", old)
	cn, _ := instance.ParseConnName("proj:reg:inst")

	start := time.Now()
	mr := d.metricRecorder(ctx, cn, tel.EnginePostgreSQL)
	if took := time.Since(start); took > delay/2 {
		t.Fatalf("metricRecorder blocked for %v on the replaced recorder's shutdown", took)
	}
	if mr == tel.MetricRecorder(old) {
		t.Fatal("recorder was not replaced once the engine was known")
	}
	select {
	case <-old.shutDown:
		t.Fatal("old recorder shut down synchronously")
	default:
	}

	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-old.shutDown:
	default:
		t.Fatal("Close returned before the replaced recorder finished shutting down")
	}
}

// TestCloseShutsDownRecordersConcurrently verifies that Close flushes all
// recorders in parallel, so the shutdown budget is shared rather than
// consumed serially by the first few instances.
func TestCloseShutsDownRecordersConcurrently(t *testing.T) {
	ctx := context.Background()
	d, err := NewDialer(ctx, WithTokenSource(mock.EmptyTokenSource{}))
	if err != nil {
		t.Fatal(err)
	}
	const n, delay = 8, 200 * time.Millisecond
	recs := make([]*slowRecorder, n)
	for i := range recs {
		recs[i] = newSlowRecorder(tel.EnginePostgreSQL, delay)
		installRecorder(t, d, fmt.Sprintf("proj:reg:inst%d", i), recs[i])
	}

	start := time.Now()
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > time.Duration(n)*delay/2 {
		t.Fatalf("Close took %v for %d recorders of %v each; shutdowns look serial", took, n, delay)
	}
	for i, r := range recs {
		select {
		case <-r.shutDown:
		default:
			t.Errorf("recorder %d was not shut down", i)
		}
	}
}

// TestMetricRecorderAfterCloseIsNull verifies that a Dial racing with Close
// cannot create a live recorder (and its export goroutine) after Close has
// torn the metrics pipeline down.
func TestMetricRecorderAfterCloseIsNull(t *testing.T) {
	ctx := context.Background()
	d, err := NewDialer(ctx, WithTokenSource(mock.EmptyTokenSource{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	cn, _ := instance.ParseConnName("proj:reg:inst")
	if _, isNull := d.metricRecorder(ctx, cn, tel.EnginePostgreSQL).(tel.NullMetricRecorder); !isNull {
		t.Fatal("metricRecorder after Close should return NullMetricRecorder")
	}
	if len(d.metricRecorders) != 0 {
		t.Fatalf("metricRecorder after Close registered %d recorder(s)", len(d.metricRecorders))
	}
}

// TestBuiltInMetricsDefaultOffOutsideDefaultUniverse verifies that in a
// non-googleapis.com universe metrics are off unless explicitly enabled, and
// that an explicit WithBuiltInMetrics(true) is honoured there.
func TestBuiltInMetricsDefaultOffOutsideDefaultUniverse(t *testing.T) {
	ctx := context.Background()
	_, conn := startFakeMetricServer(t)

	t.Run("default is off in a non-default universe", func(t *testing.T) {
		old := builtInMetricsDefault
		builtInMetricsDefault = true
		t.Cleanup(func() { builtInMetricsDefault = old })
		d, err := NewDialer(ctx,
			WithTokenSource(mock.EmptyTokenSource{}),
			WithUniverseDomain("example.universe"),
			withMetricClientOptions(option.WithGRPCConn(conn)),
		)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = d.Close() }()
		if d.enableBuiltInMetrics || d.mClient != nil {
			t.Fatal("built-in metrics should be off by default outside googleapis.com")
		}
	})

	t.Run("explicit opt-in is honoured in a non-default universe", func(t *testing.T) {
		d, err := NewDialer(ctx,
			WithTokenSource(mock.EmptyTokenSource{}),
			WithUniverseDomain("example.universe"),
			WithBuiltInMetrics(true),
			withMetricClientOptions(option.WithGRPCConn(conn)),
		)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = d.Close() }()
		if !d.enableBuiltInMetrics || d.mClient == nil {
			t.Fatal("WithBuiltInMetrics(true) should enable metrics in any universe")
		}
	})

	t.Run("default stays on in the default universe", func(t *testing.T) {
		old := builtInMetricsDefault
		builtInMetricsDefault = true
		t.Cleanup(func() { builtInMetricsDefault = old })
		d, err := NewDialer(ctx,
			WithTokenSource(mock.EmptyTokenSource{}),
			withMetricClientOptions(option.WithGRPCConn(conn)),
		)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = d.Close() }()
		if !d.enableBuiltInMetrics || d.mClient == nil {
			t.Fatal("built-in metrics should be on by default in googleapis.com")
		}
	})
}

// TestDisabledMetricsAreSilent verifies the opt-out contract end to end: with
// WithBuiltInMetrics(false), a real dial, close and Dialer.Close produce no
// export to the Monitoring API, no metrics-related debug log line, and
// nothing on the standard logger (including the OTel exporter's
// deprecation notice, which must only fire when an exporter is created).
func TestDisabledMetricsAreSilent(t *testing.T) {
	fake, conn := startFakeMetricServer(t)

	// Capture everything the process would log.
	var std syncBuffer
	oldOut, oldFlags := log.Writer(), log.Flags()
	log.SetOutput(&std)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(oldOut); log.SetFlags(oldFlags) })
	var warn syncBuffer
	restore := tel.SetWarnLoggerForTest(log.New(&warn, "", 0))
	t.Cleanup(restore)
	debug := &recordingDebugLogger{}

	inst := mock.NewFakeCSQLInstance("my-project", "my-region", "my-instance")
	d := setupDialer(t, setupConfig{
		testInstance: inst,
		reqs: []*mock.Request{
			mock.InstanceGetSuccess(inst, 1),
			mock.CreateEphemeralSuccess(inst, 1),
		},
		dialerOptions: []Option{
			// setupDialer replaces (does not extend) its default options
			// when dialerOptions is set, so restate the ones it needs; without
			// the token source NewDialer falls back to ADC, which CI lacks.
			WithTokenSource(mock.EmptyTokenSource{}),
			WithRefreshTimeout(time.Minute),
			WithBuiltInMetrics(false),
			WithContextDebugLogger(debug),
			// Even with a metric client configured, nothing must be created.
			withMetricClientOptions(option.WithGRPCConn(conn)),
		},
	})
	c, err := d.Dial(context.Background(), "my-project:my-region:my-instance")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	if got := len(fake.requests()); got != 0 {
		t.Errorf("metrics disabled, but %d export request(s) reached the Monitoring API", got)
	}
	if w := warn.String(); w != "" {
		t.Errorf("metrics disabled, but the warning logger got: %q", w)
	}
	if s := std.String(); s != "" {
		t.Errorf("metrics disabled, but the standard logger got: %q", s)
	}
	for _, line := range debug.snapshot() {
		if strings.Contains(strings.ToLower(line), "metric") {
			t.Errorf("metrics disabled, but a metrics debug line was logged: %q", line)
		}
	}
}

// recordingDebugLogger captures debug log lines.
type recordingDebugLogger struct {
	mu    sync.Mutex
	lines []string
}

func (r *recordingDebugLogger) Debugf(_ context.Context, format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, fmt.Sprintf(format, args...))
}

func (r *recordingDebugLogger) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.lines...)
}

// syncBuffer is a goroutine-safe bytes.Buffer.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestMetricLabelsIgnoreOTelEnvironment verifies that OTEL_SERVICE_NAME /
// OTEL_RESOURCE_ATTRIBUTES, which the OpenTelemetry SDK merges into every
// resource and which the exporter would by default copy onto each time
// series as metric labels, never reach the exported metrics. The descriptors
// have a fixed label schema and the Monitoring API rejects any other label,
// which would silently disable metrics in every OTel-instrumented environment.
func TestMetricLabelsIgnoreOTelEnvironment(t *testing.T) {
	t.Setenv("OTEL_SERVICE_NAME", "my-app")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "service.namespace=ns1,service.instance.id=pod-7,deployment.environment=prod")
	fake, conn := startFakeMetricServer(t)
	old := tel.DefaultExportInterval
	tel.DefaultExportInterval = time.Hour
	t.Cleanup(func() { tel.DefaultExportInterval = old })

	ctx := context.Background()
	d, err := NewDialer(ctx,
		WithTokenSource(mock.EmptyTokenSource{}),
		WithBuiltInMetrics(true),
		withMetricClientOptions(option.WithGRPCConn(conn)),
	)
	if err != nil {
		t.Fatal(err)
	}
	cn, _ := instance.ParseConnName("my-project:my-region:my-instance")
	mr := d.metricRecorder(ctx, cn, tel.EnginePostgreSQL)
	attrs := tel.Attributes{IPType: "public", DialStatus: tel.ConnectSuccess, AttemptStatus: tel.ConnectSuccess}
	mr.RecordOpenConnection(ctx, attrs)
	mr.RecordOpenConnectionCount(ctx, attrs)
	mr.RecordClosedConnectionCount(ctx, attrs)
	mr.RecordConnectLatencies(ctx, attrs, 5)
	mr.RecordConnectionDuration(ctx, attrs, 1)
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	allowedMetricLabels := map[string]bool{
		"instance_auth_type": true, "instance_ip_type": true, "status": true, "connection_part": true,
	}
	var seen int
	for _, req := range fake.requests() {
		for _, ts := range req.GetTimeSeries() {
			seen++
			for k := range ts.GetMetric().GetLabels() {
				if !allowedMetricLabels[k] {
					t.Errorf("%s: unexpected metric label %q (from the OTel environment?)", ts.GetMetric().GetType(), k)
				}
			}
			// The monitored resource must still be fully populated.
			rl := ts.GetResource().GetLabels()
			for _, k := range []string{"resource_container", "resource_id", "client_uid", "region", "connector_type", "connector_version", "database_engine_type"} {
				if rl[k] == "" {
					t.Errorf("%s: resource label %q is empty", ts.GetMetric().GetType(), k)
				}
			}
			if ts.GetResource().GetType() != "cloudsql.googleapis.com/InstanceClient" {
				t.Errorf("resource type = %q", ts.GetResource().GetType())
			}
		}
	}
	if seen < 5 {
		t.Fatalf("expected the 5 metrics to be exported, saw %d time series", seen)
	}
}

// TestEnabledMetricsWriteNothingToStandardLogger verifies the quiet contract
// on the *enabled*, healthy path: creating a Dialer with metrics on,
// recording, exporting and closing must not write anything to the process's
// standard logger (which third-party exporters may use for notices).
func TestEnabledMetricsWriteNothingToStandardLogger(t *testing.T) {
	var std syncBuffer
	oldOut, oldFlags := log.Writer(), log.Flags()
	log.SetOutput(&std)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(oldOut); log.SetFlags(oldFlags) })
	fake, conn := startFakeMetricServer(t)
	old := tel.DefaultExportInterval
	tel.DefaultExportInterval = time.Hour
	t.Cleanup(func() { tel.DefaultExportInterval = old })

	ctx := context.Background()
	d, err := NewDialer(ctx,
		WithTokenSource(mock.EmptyTokenSource{}),
		WithBuiltInMetrics(true),
		withMetricClientOptions(option.WithGRPCConn(conn)),
	)
	if err != nil {
		t.Fatal(err)
	}
	cn, _ := instance.ParseConnName("my-project:my-region:my-instance")
	mr := d.metricRecorder(ctx, cn, tel.EnginePostgreSQL)
	mr.RecordOpenConnectionCount(ctx, tel.Attributes{IPType: "public", AttemptStatus: tel.ConnectSuccess})
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if len(fake.requests()) == 0 {
		t.Fatal("expected an export")
	}
	if s := std.String(); s != "" {
		t.Fatalf("enabled metrics wrote to the standard logger: %q", s)
	}
}

// TestMetricRecorderKeyIgnoresDomainName verifies that an instance dialed by
// DNS name and by connection name shares one recorder, i.e. one monitored
// resource, rather than two conflicting cumulative series.
func TestMetricRecorderKeyIgnoresDomainName(t *testing.T) {
	plain, err := instance.ParseConnName("my-project:my-region:my-instance")
	if err != nil {
		t.Fatal(err)
	}
	dns, err := instance.ParseConnNameWithDomainName("my-project:my-region:my-instance", "db.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if plain == dns {
		t.Fatal("test setup: ConnNames should differ by domain name")
	}
	if newMetricRecorderKey(plain) != newMetricRecorderKey(dns) {
		t.Fatalf("recorder keys differ: %v vs %v", newMetricRecorderKey(plain), newMetricRecorderKey(dns))
	}
	d, err := NewDialer(context.Background(), WithTokenSource(mock.EmptyTokenSource{}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	rec := &countingRecorder{engine: tel.EnginePostgreSQL}
	installRecorder(t, d, "my-project:my-region:my-instance", rec)
	if got := d.metricRecorder(context.Background(), dns, tel.EnginePostgreSQL); got != tel.MetricRecorder(rec) {
		t.Fatal("DNS-named dial did not reuse the connection-name recorder")
	}
}

// TestCloseDoesNotHoldDialerLockDuringFlush verifies that the metrics flush
// in Close (network I/O, up to metricShutdownTimeout) runs without d.lock,
// which connections' error paths need (removeCached), and without metricsMu,
// which a racing Dial needs.
func TestCloseDoesNotHoldDialerLockDuringFlush(t *testing.T) {
	d, err := NewDialer(context.Background(), WithTokenSource(mock.EmptyTokenSource{}))
	if err != nil {
		t.Fatal(err)
	}
	const delay = 400 * time.Millisecond
	installRecorder(t, d, "proj:reg:inst", newSlowRecorder(tel.EnginePostgreSQL, delay))

	closeDone := make(chan struct{})
	go func() { _ = d.Close(); close(closeDone) }()
	time.Sleep(50 * time.Millisecond) // let Close reach the flush

	locked := make(chan time.Duration, 2)
	go func() {
		s := time.Now()
		d.lock.Lock()
		d.lock.Unlock()
		locked <- time.Since(s)
	}()
	go func() {
		s := time.Now()
		d.metricsMu.Lock()
		d.metricsMu.Unlock()
		locked <- time.Since(s)
	}()
	for i := 0; i < 2; i++ {
		select {
		case took := <-locked:
			if took > delay/2 {
				t.Errorf("a Dialer lock was held for %v during the metrics flush", took)
			}
		case <-time.After(2 * delay):
			t.Fatal("a Dialer lock was not released during the metrics flush")
		}
	}
	<-closeDone
}

// TestConcurrentCloseIsSafe verifies that Close can be called from several
// goroutines at once without panicking (closing a closed channel).
func TestConcurrentCloseIsSafe(t *testing.T) {
	for i := 0; i < 20; i++ {
		d, err := NewDialer(context.Background(), WithTokenSource(mock.EmptyTokenSource{}))
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for j := 0; j < 8; j++ {
			wg.Add(1)
			go func() { defer wg.Done(); _ = d.Close() }()
		}
		wg.Wait()
	}
}
