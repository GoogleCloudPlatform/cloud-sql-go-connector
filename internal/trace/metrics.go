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

// NewMetricsCollector registers all views. Without registering views, metrics will not
// be reported. If any names of the registered views conflict, this function
// returns an error to indicate a configuration problem.
func NewMetricsCollector() (*MetricsCollector, error) {
	mc := &MetricsCollector{
		mLatencyMS: stats.Int64(
			"/cloudsqlconn/latency",
			"The latency in milliseconds per Dial",
			stats.UnitMilliseconds,
		),
		mConnections: stats.Int64(
			"/cloudsqlconn/connection",
			"A connect or disconnect event to Cloud SQL",
			stats.UnitDimensionless,
		),
	}

	latencyView := &view.View{
		Name:        "/cloudsqlconn/dial_latency",
		Measure:     mc.mLatencyMS,
		Description: "The distribution of dialer latencies (ms)",
		// Latency in buckets, e.g., >=0ms, >=100ms, etc.
		Aggregation: view.Distribution(0, 5, 25, 100, 250, 500, 1000, 2000, 5000, 30000),
		TagKeys:     []tag.Key{keyInstance, keyDialerID},
	}
	connectionsView := &view.View{
		Name:        "/cloudsqlconn/open_connections",
		Measure:     mc.mConnections,
		Description: "The current number of open Cloud SQL connections",
		Aggregation: view.LastValue(),
		TagKeys:     []tag.Key{keyInstance, keyDialerID},
	}
	if err := view.Register(latencyView, connectionsView); err != nil {
		return nil, fmt.Errorf("failed to initialize metrics: %v", err)
	}
	return mc, nil
}

// MetricsCollector encapsulates all tracked metrics.
type MetricsCollector struct {
	mLatencyMS   *stats.Int64Measure
	mConnections *stats.Int64Measure
}

// RecordDialLatency records a latency value for a call to dial.
func (mc *MetricsCollector) RecordDialLatency(ctx context.Context, instance, dialerID string, latency int64) {
	// tag.New creates a new context and errors only if the new tag already
	// exists in the provided context. Since we're adding tags within this
	// package only, we can be confident that there were be no duplicate tags
	// and so can ignore the error.
	ctx, _ = tag.New(ctx, tag.Upsert(keyInstance, instance), tag.Upsert(keyDialerID, dialerID))
	stats.Record(ctx, mc.mLatencyMS.M(latency))
}

// RecordOpenConnections records the number of open connections
func (mc *MetricsCollector) RecordOpenConnections(ctx context.Context, num int64, dialerID, instance string) {
	// Why are we ignoring this error? See above under RecordDialLatency.
	ctx, _ = tag.New(ctx, tag.Upsert(keyInstance, instance), tag.Upsert(keyDialerID, dialerID))
	stats.Record(ctx, mc.mConnections.M(num))
}
