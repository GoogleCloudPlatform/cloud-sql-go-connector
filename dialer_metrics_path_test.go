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
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/cloudsqlconn/errtype"
	"cloud.google.com/go/cloudsqlconn/instance"
	"cloud.google.com/go/cloudsqlconn/internal/mock"
	"cloud.google.com/go/cloudsqlconn/internal/tel"
	sqlpb "cloud.google.com/go/sql/apiv1beta4/sqlpb"
	"go.opencensus.io/stats/view"
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
	d.metricRecorders[cn] = rec
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
