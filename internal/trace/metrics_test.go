package trace_test

import (
	"testing"

	"cloud.google.com/go/cloudsqlconn/internal/trace"
)

func TestMetricsInitializes(t *testing.T) {
	if err := trace.InitMetrics(); err != nil {
		t.Fatalf("want no error, got = %v", err)
	}
}
