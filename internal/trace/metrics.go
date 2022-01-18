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

	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"
)

var (
	keyInstance, _ = tag.NewKey("cloudsql_instance")
	keyDialerID, _ = tag.NewKey("cloudsql_dialer_id")
)

var (
	mLatencyMS = stats.Int64(
		"/cloudsqlconn/latency",
		"The latency in milliseconds per Dial",
		stats.UnitMilliseconds,
	)
	latencyView = &view.View{
		Name:        "/cloudsqlconn/dial_latency",
		Measure:     mLatencyMS,
		Description: "The distribution of dialer latencies (ms)",
		// Latency in buckets, e.g., >=0ms, >=100ms, etc.
		Aggregation: view.Distribution(0, 5, 25, 100, 250, 500, 1000, 2000, 5000, 30000),
		TagKeys:     []tag.Key{keyInstance, keyDialerID},
	}
)

var (
	mConnections = stats.Int64(
		"/cloudsqlconn/connection",
		"A connect or disconnect event to Cloud SQL",
		stats.UnitDimensionless,
	)
	connectionsView = &view.View{
		Name:        "/cloudsqlconn/open_connections",
		Measure:     mConnections,
		Description: "The sum of Cloud SQL connections",
		Aggregation: view.Sum(),
		TagKeys:     []tag.Key{keyInstance, keyDialerID},
	}
)

// RecordDialLatency records a latency value for a call to dial.
func RecordDialLatency(ctx context.Context, instance, dialerID string, latency int64) {
	// tag.New creates a new context and errors only if the new tag already
	// exists in the provided context. Since we're adding tags within this
	// package only, we can be confident that there were be no duplicate tags
	// and so can ignore the error.
	ctx, _ = tag.New(ctx, tag.Upsert(keyInstance, instance), tag.Upsert(keyDialerID, dialerID))
	stats.Record(ctx, mLatencyMS.M(latency))
}

// RecordConnectionOpen reports a connection event.
func RecordConnectionOpen(ctx context.Context, instance, dialerID string) {
	// Why are we ignoring this error? See above under RecordDialLatency.
	ctx, _ = tag.New(ctx, tag.Upsert(keyInstance, instance), tag.Upsert(keyDialerID, dialerID))
	stats.Record(ctx, mConnections.M(1))
}

// RecordConnectionClose records a disconnect event.
func RecordConnectionClose(ctx context.Context, instance, dialerID string) {
	// Why are we ignoring this error? See above under RecordDialLatency.
	ctx, _ = tag.New(ctx, tag.Upsert(keyInstance, instance), tag.Upsert(keyDialerID, dialerID))
	stats.Record(ctx, mConnections.M(-1))
}

// InitMetrics registers all views. Without registering views, metrics will not
// be reported. If any names of the registered views conflict, this function
// returns an error to indicate a configuration problem.
func InitMetrics() error {
	if err := view.Register(latencyView, connectionsView); err != nil {
		return fmt.Errorf("failed to initialize metrics: %v", err)
	}
	return nil
}
