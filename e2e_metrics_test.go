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

package cloudsqlconn_test

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"math/rand/v2"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cloud.google.com/go/cloudsqlconn"
	"cloud.google.com/go/cloudsqlconn/instance"
	"cloud.google.com/go/cloudsqlconn/internal/tel"
	monitoring "cloud.google.com/go/monitoring/apiv3/v2"
	"cloud.google.com/go/monitoring/apiv3/v2/monitoringpb"
	"golang.org/x/oauth2"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// These end-to-end tests exercise built-in metrics against the real Cloud SQL
// instance and the real Cloud Monitoring API configured for the e2e suite.
// They cover two properties that unit tests with a mock server cannot:
//
//   - metrics actually arrive in Cloud Monitoring with the documented labels;
//   - when the metrics pipeline is broken (unreachable endpoint, bad
//     credentials), the application is unaffected: dials succeed, dial
//     latency is unchanged, Close returns promptly, and the only output is
//     the single standard-logger warning.

// e2eLogger captures debug log lines.
type e2eLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *e2eLogger) Debugf(_ context.Context, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *e2eLogger) find(substr string) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, s := range l.lines {
		if strings.Contains(s, substr) {
			out = append(out, s)
		}
	}
	return out
}

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

// scaleMetricTimings shortens the export interval and backoffs for the
// duration of a test so failures and retries are observable in seconds.
func scaleMetricTimings(t *testing.T, interval time.Duration) {
	t.Helper()
	oldI := tel.DefaultExportInterval
	oldPI, oldPM := tel.PermanentExportErrorInitialBackoff, tel.PermanentExportErrorMaxBackoff
	oldTI, oldTM := tel.TransientExportErrorInitialBackoff, tel.TransientExportErrorMaxBackoff
	tel.DefaultExportInterval = interval
	tel.PermanentExportErrorInitialBackoff, tel.PermanentExportErrorMaxBackoff = 5*interval, 20*interval
	tel.TransientExportErrorInitialBackoff, tel.TransientExportErrorMaxBackoff = 3*interval, 12*interval
	t.Cleanup(func() {
		tel.DefaultExportInterval = oldI
		tel.PermanentExportErrorInitialBackoff, tel.PermanentExportErrorMaxBackoff = oldPI, oldPM
		tel.TransientExportErrorInitialBackoff, tel.TransientExportErrorMaxBackoff = oldTI, oldTM
	})
}

// requireMetricsE2EVars needs only the instance connection name; the
// metrics tests do not log in to the database.
func requireMetricsE2EVars(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping metrics integration tests")
	}
	if postgresConnName == "" {
		t.Fatal("'POSTGRES_CONNECTION_NAME' env var not set")
	}
}

// dialNTimes dials the instance n times, closing each connection, and
// returns the sorted dial latencies.
func dialNTimes(ctx context.Context, t *testing.T, d *cloudsqlconn.Dialer, icn string, n int) []time.Duration {
	t.Helper()
	lat := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		start := time.Now()
		c, err := d.Dial(ctx, icn)
		if err != nil {
			t.Fatalf("dial %d failed: %v", i, err)
		}
		lat = append(lat, time.Since(start))
		_ = c.Close()
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	return lat
}

// TestMetricsE2EExport verifies that all five built-in metrics for a real
// dial arrive in Cloud Monitoring with the documented label values. It skips
// (with the exact remediation) when the test identity lacks the Monitoring
// roles on the test project.
func TestMetricsE2EExport(t *testing.T) {
	requireMetricsE2EVars(t)
	ctx := context.Background()

	cn, err := instance.ParseConnName(postgresConnName)
	if err != nil {
		t.Fatal(err)
	}
	appName := fmt.Sprintf("e2e-metrics-%d", rand.IntN(1_000_000))
	logger := &e2eLogger{}
	var warn syncBuffer
	restore := tel.SetWarnLoggerForTest(log.New(&warn, "", 0))
	t.Cleanup(restore)

	d, err := cloudsqlconn.NewDialer(ctx,
		cloudsqlconn.WithBuiltInMetrics(true),
		cloudsqlconn.WithApplicationName(appName),
		cloudsqlconn.WithContextDebugLogger(logger),
	)
	if err != nil {
		t.Fatal(err)
	}
	clientUID := cloudsqlconn.DialerIDForTest(d)

	c, err := d.Dial(ctx, postgresConnName)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	time.Sleep(time.Second) // give connection_durations a non-trivial value
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	// Close flushes the exporters synchronously (bounded by cloudsqlconn.MetricShutdownTimeoutForTest).
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	// If the identity cannot write metrics, say exactly what to grant and
	// skip rather than fail: the rest of the e2e suite is still valid.
	if failed := logger.find("built-in metrics export failed"); len(failed) > 0 {
		principal := "<the e2e service account>"
		if p := cloudsqlconn.DetectPrincipalForTest(ctx); p != "" {
			principal = p
		}
		t.Skipf("metrics export failed from the e2e identity; grant Monitoring roles on project %s and re-run:\n"+
			"  gcloud projects add-iam-policy-binding %s --member=serviceAccount:%s --role=roles/monitoring.metricWriter\n"+
			"  gcloud projects add-iam-policy-binding %s --member=serviceAccount:%s --role=roles/monitoring.viewer\n"+
			"debug: %s", cn.Project(), cn.Project(), principal, cn.Project(), principal, failed[0])
	}
	if w := warn.String(); w != "" {
		t.Fatalf("unexpected standard-logger output during a healthy export: %q", w)
	}

	// Poll Cloud Monitoring for this process's client_uid.
	mc, err := monitoring.NewMetricClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mc.Close() }()

	want := map[string]bool{
		"open_connection_count":   false,
		"connect_latencies":       false,
		"open_connections":        false,
		"closed_connection_count": false,
		"connection_durations":    false,
	}
	var sawResource map[string]string
	var sawMetricLabels = map[string]map[string]string{}
	// ListTimeSeries accepts exactly one metric.type per request, so query
	// each metric separately.
	listOne := func(name string) (*monitoringpb.TimeSeries, error) {
		it := mc.ListTimeSeries(ctx, &monitoringpb.ListTimeSeriesRequest{
			Name: "projects/" + cn.Project(),
			Filter: fmt.Sprintf(`metric.type = "cloudsql.googleapis.com/client/connector/%s" AND resource.labels.client_uid = %q`,
				name, clientUID),
			Interval: &monitoringpb.TimeInterval{
				StartTime: timestamppb.New(time.Now().Add(-10 * time.Minute)),
				EndTime:   timestamppb.New(time.Now()),
			},
			View: monitoringpb.ListTimeSeriesRequest_FULL,
		})
		ts, err := it.Next()
		if err == iterator.Done {
			return nil, nil
		}
		return ts, err
	}
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		for name, ok := range want {
			if ok {
				continue
			}
			ts, err := listOne(name)
			if err != nil {
				if status.Code(err) == codes.PermissionDenied {
					t.Skipf("identity cannot read metrics (grant roles/monitoring.viewer on %s): %v", cn.Project(), err)
				}
				t.Fatalf("ListTimeSeries(%s): %v", name, err)
			}
			if ts != nil {
				want[name] = true
				sawResource = ts.GetResource().GetLabels()
				sawMetricLabels[name] = ts.GetMetric().GetLabels()
			}
		}
		all := true
		for _, ok := range want {
			all = all && ok
		}
		if all {
			break
		}
		time.Sleep(10 * time.Second)
	}
	for name, ok := range want {
		if !ok {
			t.Errorf("metric %s did not arrive in Cloud Monitoring within 3 minutes", name)
		}
	}
	if t.Failed() {
		return
	}

	// Label contract (see internal/tel for the full set).
	checks := map[string]string{
		"application_name":     appName,
		"database_engine_type": tel.EnginePostgreSQL,
		"connector_type":       tel.ConnectorTypeGo,
		"region":               cn.Region(),
		"resource_id":          cn.Project() + ":" + cn.Name(),
	}
	for k, v := range checks {
		if got := sawResource[k]; got != v {
			t.Errorf("resource label %s = %q, want %q", k, got, v)
		}
	}
	if v := sawResource["connector_version"]; strings.ContainsAny(v, "\r\n") || v == "" {
		t.Errorf("connector_version = %q", v)
	}
	if !tel.IsValidComputePlatform(sawResource["compute_platform"]) {
		t.Errorf("compute_platform = %q is not an allowed value", sawResource["compute_platform"])
	}
	if got := sawMetricLabels["open_connection_count"]["status"]; got != tel.ConnectSuccess {
		t.Errorf("open_connection_count status = %q, want %q", got, tel.ConnectSuccess)
	}
	if got := sawMetricLabels["connect_latencies"]["instance_ip_type"]; got != tel.IPTypePublic && got != tel.IPTypePrivate && got != tel.IPTypePSC {
		t.Errorf("instance_ip_type = %q is not a resolved IP type", got)
	}
}

// TestMetricsE2EFailOpenUnreachableEndpoint verifies that when the Monitoring
// API cannot be reached at all, connectivity is unaffected: dials succeed,
// dial latency matches a metrics-off dialer, Close returns promptly, and
// nothing is written to the standard logger (transient errors are quiet).
func TestMetricsE2EFailOpenUnreachableEndpoint(t *testing.T) {
	requireMetricsE2EVars(t)
	ctx := context.Background()
	scaleMetricTimings(t, 2*time.Second)
	var warn syncBuffer
	restore := tel.SetWarnLoggerForTest(log.New(&warn, "", 0))
	t.Cleanup(restore)
	logger := &e2eLogger{}

	const dials = 15
	baseline, err := cloudsqlconn.NewDialer(ctx, cloudsqlconn.WithBuiltInMetrics(false))
	if err != nil {
		t.Fatal(err)
	}
	baseLat := dialNTimes(ctx, t, baseline, postgresConnName, dials)
	_ = baseline.Close()

	// 10.255.255.1 is unroutable: every export times out (DeadlineExceeded /
	// Unavailable), the transient tier.
	broken, err := cloudsqlconn.NewDialer(ctx,
		cloudsqlconn.WithBuiltInMetrics(true),
		cloudsqlconn.WithContextDebugLogger(logger),
		cloudsqlconn.WithMetricClientOptionsForTest(
			option.WithEndpoint("10.255.255.1:443"),
			option.WithGRPCDialOption(grpc.WithUnaryInterceptor(shortDeadline(1500*time.Millisecond))),
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	brokenLat := dialNTimes(ctx, t, broken, postgresConnName, dials)
	// Let a few export attempts fail in the background.
	time.Sleep(8 * time.Second)

	closeStart := time.Now()
	if err := broken.Close(); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(closeStart); took > cloudsqlconn.MetricShutdownTimeoutForTest+2*time.Second {
		t.Errorf("Close took %v with an unreachable metrics endpoint; want <= %v", took, cloudsqlconn.MetricShutdownTimeoutForTest+2*time.Second)
	}

	p50 := func(l []time.Duration) time.Duration { return l[len(l)/2] }
	if brokenLat[len(brokenLat)/2] > 2*p50(baseLat)+100*time.Millisecond {
		t.Errorf("dial p50 with broken metrics %v vs baseline %v: metrics must not affect the dial path", p50(brokenLat), p50(baseLat))
	}
	if len(logger.find("built-in metrics export failed")) == 0 {
		t.Error("expected at least one debug line about the failing export")
	}
	if w := warn.String(); w != "" {
		t.Errorf("transient export failures must not write to the standard logger, got %q", w)
	}
}

// TestMetricsE2EFailOpenBadCredentials verifies the permanent-error path
// against the real API: an invalid token yields a real Unauthenticated,
// connectivity is unaffected, exactly one standard-logger line is written,
// and export is suspended.
func TestMetricsE2EFailOpenBadCredentials(t *testing.T) {
	requireMetricsE2EVars(t)
	ctx := context.Background()
	scaleMetricTimings(t, 2*time.Second)
	var warn syncBuffer
	restore := tel.SetWarnLoggerForTest(log.New(&warn, "", 0))
	t.Cleanup(restore)
	logger := &e2eLogger{}

	var calls atomic.Int32
	count := func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, inv grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		err := inv(ctx, method, req, reply, cc, opts...)
		if strings.HasSuffix(method, "CreateServiceTimeSeries") {
			calls.Add(1)
		}
		return err
	}
	d, err := cloudsqlconn.NewDialer(ctx,
		cloudsqlconn.WithBuiltInMetrics(true),
		cloudsqlconn.WithContextDebugLogger(logger),
		cloudsqlconn.WithMetricClientOptionsForTest(
			option.WithTokenSource(oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "not-a-valid-token"})),
			option.WithGRPCDialOption(grpc.WithUnaryInterceptor(count)),
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	lat := dialNTimes(ctx, t, d, postgresConnName, 5)
	if lat[len(lat)-1] > 10*time.Second {
		t.Errorf("dial took %v", lat[len(lat)-1])
	}
	// Enough ticks for the first attempt and to prove the suspension holds.
	time.Sleep(12 * time.Second)
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	if n := calls.Load(); n < 1 || n > 3 {
		t.Errorf("with a permanent error expected 1-3 export attempts in the window (backoff), got %d", n)
	}
	w := warn.String()
	if c := strings.Count(w, "cloudsqlconn: built-in metrics export failed"); c != 1 {
		t.Errorf("want exactly one standard-logger warning, got %d: %q", c, w)
	}
	for _, want := range []string{"roles/monitoring.metricWriter", "WithBuiltInMetrics(false)"} {
		if !strings.Contains(w, want) {
			t.Errorf("warning missing %q: %q", want, w)
		}
	}
	if len(logger.find("suspending export")) == 0 {
		t.Error("expected a debug line about suspension")
	}
}

// shortDeadline bounds each metrics RPC so an unreachable endpoint fails
// quickly instead of waiting for the exporter's default timeout.
func shortDeadline(d time.Duration) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, inv grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		ctx, cancel := context.WithTimeout(ctx, d)
		defer cancel()
		return inv(ctx, method, req, reply, cc, opts...)
	}
}
