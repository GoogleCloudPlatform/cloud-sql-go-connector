// Copyright 2022 Google LLC
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

package trace

import (
	"context"
	"fmt"
	"sync"

	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"
)

var (
	keyInstance, _ = tag.NewKey("cloudsql_instance")
	keyDialerID, _ = tag.NewKey("cloudsql_dialer_id")

	mLatencyMS = stats.Int64(
		"/cloudsqlconn/latency",
		"The latency in milliseconds per Dial",
		stats.UnitMilliseconds,
	)
	mConnections = stats.Int64(
		"/cloudsqlconn/connection",
		"A connect or disconnect event to Cloud SQL",
		stats.UnitDimensionless,
	)
	mDialError = stats.Int64(
		"/cloudsqlconn/dial_failure",
		"A failure to successfully dial a Cloud SQL instance",
		stats.UnitDimensionless,
	)

	latencyView = &view.View{
		Name:        "/cloudsqlconn/dial_latency",
		Measure:     mLatencyMS,
		Description: "The distribution of dialer latencies (ms)",
		// Latency in buckets, e.g., >=0ms, >=100ms, etc.
		Aggregation: view.Distribution(0, 5, 25, 100, 250, 500, 1000, 2000, 5000, 30000),
		TagKeys:     []tag.Key{keyInstance, keyDialerID},
	}
	connectionsView = &view.View{
		Name:        "/cloudsqlconn/open_connections",
		Measure:     mConnections,
		Description: "The current number of open Cloud SQL connections",
		Aggregation: view.LastValue(),
		TagKeys:     []tag.Key{keyInstance, keyDialerID},
	}
	dialFailureView = &view.View{
		Name:        "/cloudsqlconn/dial_failure_count",
		Measure:     mDialError,
		Description: "The number of failed dial attempts",
		Aggregation: view.Count(),
		TagKeys:     []tag.Key{keyInstance, keyDialerID},
	}


	registerOnce sync.Once
	registerErr  error
)

// InitMetrics registers all views once. Without registering views, metrics will
// not be reported. If any names of the registered views conflict, this function
// returns an error to indicate an internal configuration problem.
func InitMetrics() error {
	registerOnce.Do(func() {
		if rErr := view.Register(latencyView, connectionsView, dialFailureView); rErr != nil {
			registerErr = fmt.Errorf("failed to initialize metrics: %v", rErr)
		}
	})
	return registerErr
}

// RecordDialLatency records a latency value for a call to dial.
func RecordDialLatency(ctx context.Context, instance, dialerID string, latency int64) {
	// tag.New creates a new context and errors only if the new tag already
	// exists in the provided context. Since we're adding tags within this
	// package only, we can be confident that there were be no duplicate tags
	// and so can ignore the error.
	ctx, _ = tag.New(ctx, tag.Upsert(keyInstance, instance), tag.Upsert(keyDialerID, dialerID))
	stats.Record(ctx, mLatencyMS.M(latency))
}

// RecordOpenConnections records the number of open connections
func RecordOpenConnections(ctx context.Context, num int64, dialerID, instance string) {
	// Why are we ignoring this error? See above under RecordDialLatency.
	ctx, _ = tag.New(ctx, tag.Upsert(keyInstance, instance), tag.Upsert(keyDialerID, dialerID))
	stats.Record(ctx, mConnections.M(num))
}

// RecordDialError reports a failed dial attempt. If err is nil, RecordDialError
// is a no-op.
func RecordDialError(ctx context.Context, instance, dialerID string, err error) {
	if err == nil {
		return
	}
	// Why are we ignoring this error? See above under RecordDialLatency.
	ctx, _ = tag.New(ctx, tag.Upsert(keyInstance, instance), tag.Upsert(keyDialerID, dialerID))
	stats.Record(ctx, mDialError.M(1))
}
