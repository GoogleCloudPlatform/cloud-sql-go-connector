// Copyright 2022 Google LLC
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
package cloudsqlconn

import (
	"context"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/cloudsqlconn/internal/mock"
	"go.opencensus.io/stats/view"
)

type spyMetricsExporter struct {
	mu   sync.Mutex
	data []*view.Data
}

func (e *spyMetricsExporter) ExportView(vd *view.Data) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.data = append(e.data, vd)
}

type metric struct {
	name string
	data view.AggregationData
}

func (e *spyMetricsExporter) Data() []metric {
	e.mu.Lock()
	defer e.mu.Unlock()
	var res []metric
	for _, d := range e.data {
		for _, r := range d.Rows {
			res = append(res, metric{name: d.View.Name, data: r.Data})
		}
	}
	return res
}

// wantLastValueMetric ensures the provided metrics include a metric with the
// wanted name and at least data point.
func wantLastValueMetric(t *testing.T, wantName string, ms []metric) {
	gotNames := make(map[string]view.AggregationData)
	for _, m := range ms {
		gotNames[m.name] = m.data
		_, ok := m.data.(*view.LastValueData)
		if m.name == wantName && ok {
			return
		}
	}
	t.Fatalf("metric name want = %v with LastValueData, all metrics = %#v", wantName, gotNames)
}

// wantDistributionMetric ensures the provided metrics include a metric with the
// wanted name and at least one data point.
func wantDistributionMetric(t *testing.T, wantName string, ms []metric) {
	gotNames := make(map[string]view.AggregationData)
	for _, m := range ms {
		gotNames[m.name] = m.data
		_, ok := m.data.(*view.DistributionData)
		if m.name == wantName && ok {
			return
		}
	}
	t.Fatalf("metric name want = %v with DistributionData, all metrics = %#v", wantName, gotNames)
}

// wantCountMetric ensures the provided metrics include a metric with the wanted
// name and at least one data point.
func wantCountMetric(t *testing.T, wantName string, ms []metric) {
	gotNames := make(map[string]view.AggregationData)
	for _, m := range ms {
		gotNames[m.name] = m.data
		_, ok := m.data.(*view.CountData)
		if m.name == wantName && ok {
			return
		}
	}
	t.Fatalf("metric name want = %v with CountData, all metrics = %#v", wantName, gotNames)
}

func TestDialerWithMetrics(t *testing.T) {
	spy := &spyMetricsExporter{}
	view.RegisterExporter(spy)
	defer view.UnregisterExporter(spy)
	view.SetReportingPeriod(time.Millisecond)

	inst := mock.NewFakeCSQLInstance("my-project", "my-region", "my-instance")
	svc, cleanup, err := mock.NewSQLAdminService(
		context.Background(),
		mock.InstanceGetSuccess(inst, 1),
		mock.CreateEphemeralSuccess(inst, 1),
	)
	if err != nil {
		t.Fatalf("failed to init SQLAdminService: %v", err)
	}
	stop := mock.StartServerProxy(t, inst)
	defer func() {
		stop()
		if err := cleanup(true); err != nil {
			t.Fatalf("%v", err)
		}
	}()

	d, err := NewDialer(context.Background(),
		WithDefaultDialOptions(WithPublicIP()),
		WithTokenSource(mock.EmptyTokenSource{}),
	)
	if err != nil {
		t.Fatalf("expected NewDialer to succeed, but got error: %v", err)
	}
	d.sqladmin = svc

	// dial a good instance
	conn, err := d.Dial(context.Background(), "my-project:my-region:my-instance")
	if err != nil {
		t.Fatalf("expected Dial to succeed, but got error: %v", err)
	}
	defer conn.Close()
	// dial a bogus instance
	_, err = d.Dial(context.Background(), "my-project:my-region:notaninstance")
	if err == nil {
		t.Fatal("expected Dial to fail, but got no error")
	}

	time.Sleep(10 * time.Millisecond) // allow exporter a chance to run

	// success metrics
	wantLastValueMetric(t, "/cloudsqlconn/open_connections", spy.Data())
	wantDistributionMetric(t, "/cloudsqlconn/dial_latency", spy.Data())
	wantCountMetric(t, "/cloudsqlconn/refresh_success_count", spy.Data())

	// failure metrics from dialing bogus instance
	wantCountMetric(t, "/cloudsqlconn/dial_failure_count", spy.Data())
	wantCountMetric(t, "/cloudsqlconn/refresh_failure_count", spy.Data())
}
