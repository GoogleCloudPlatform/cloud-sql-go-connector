// Copyright 2025 Google LLC
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
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/cloudsqlconn/internal/tel"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"

	monitoringpb "cloud.google.com/go/monitoring/apiv3/v2/monitoringpb"
)

const bufSize = 4 * 1024 * 1024

type nullLogger struct {
	t *testing.T
}

func (n nullLogger) Debugf(_ context.Context, format string, args ...any) {
	n.t.Logf(format, args...)
}

type mockServer struct {
	mu      sync.Mutex
	gotReqs []*monitoringpb.CreateTimeSeriesRequest
	monitoringpb.MetricServiceServer
}

func (m *mockServer) CreateServiceTimeSeries(_ context.Context, req *monitoringpb.CreateTimeSeriesRequest) (*emptypb.Empty, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gotReqs = append(m.gotReqs, req)
	return &emptypb.Empty{}, nil
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
		"resource_container": "myproject",
		"region":             "some-location",
		"resource_id":        "some-instance",
		"client_uid":         "some-uid",
		"connector_type":     "go",
		"connector_version":  "1.2.3",
		"application_name":   "",
		"client_region":      "",
		"compute_platform":   "",
		"database_engine_type": "",
	}
	mock, conn, cleanup := setupMockServer(t)
	t.Cleanup(cleanup)

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
				"instance_ip_type":   "",
				"status":             "success",
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			ctx := context.Background()
			mr := tel.NewMetricRecorder(ctx, nullLogger{t}, tc.cfg, option.WithGRPCConn(conn))

			tc.action(ctx, mr, tc.attrs)

			mock.Verify(t, tc.wantProject, tc.wantResourceType, tc.wantMetricType, tc.wantResourceLabels, tc.wantMetricLabels)
		})
	}

}