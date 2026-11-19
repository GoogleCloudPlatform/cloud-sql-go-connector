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

package cloudsqlconn

import "context"

// Test-only accessors for the external (cloudsqlconn_test) e2e tests.

// WithMetricClientOptionsForTest appends options for the built-in metrics
// client, e.g. to point it at an unreachable endpoint.
var WithMetricClientOptionsForTest = withMetricClientOptions

// DialerIDForTest returns the client_uid the Dialer reports in metrics.
func DialerIDForTest(d *Dialer) string { return d.dialerID }

// DetectPrincipalForTest returns the best-effort ADC principal.
func DetectPrincipalForTest(ctx context.Context) string {
	return detectPrincipal(ctx, &dialerConfig{})
}

// MetricShutdownTimeoutForTest is the bound on metric flushing in Close.
const MetricShutdownTimeoutForTest = metricShutdownTimeout
