package trace

import (
	"context"
	"fmt"

	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"
)

var keyInstance, _ = tag.NewKey("cloudsql_instance")

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
		Aggregation: view.Distribution(0, 100, 200, 300, 400, 500, 600, 800, 1000, 2000, 4000),
		TagKeys:     []tag.Key{keyInstance},
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
		TagKeys:     []tag.Key{keyInstance},
	}
)

// RecordDialLatency records a latency value for a call to dial.
func RecordDialLatency(ctx context.Context, instance string, latency int64) {
	// Why are we ignoring this error? See below under RecordConnections.
	ctx, _ = tag.New(ctx, tag.Upsert(keyInstance, instance))
	stats.Record(ctx, mLatencyMS.M(latency))
}

// RecordConnection reports a connection event.
func RecordConnection(ctx context.Context, instance string) {
	// tag.New creates a new context and errors only if the new tag already
	// exists in the provided context. Since we're adding tags within this
	// package only, we can be confident that there were be no duplicate tags
	// and so can ignore the error.
	ctx, _ = tag.New(ctx, tag.Upsert(keyInstance, instance))
	stats.Record(ctx, mConnections.M(1))
}

// RecordDisconnect records a disconnect event.
func RecordDisconnect(ctx context.Context, instance string) {
	ctx, _ = tag.New(ctx, tag.Upsert(keyInstance, instance))
	stats.Record(ctx, mConnections.M(-1))
}

// InitMetrics registers all views. Without registering views, metrics will not
// be reported.
func InitMetrics() error {
	if err := view.Register(latencyView, connectionsView); err != nil {
		return fmt.Errorf("failed to initialize metrics: %v", err)
	}
	return nil
}
