// Copyright 2024 Google LLC
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

package cloudsql

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"google.golang.org/api/googleapi"
)

func TestRetryExponentialBackoff(t *testing.T) {
	tcs := []struct {
		attempt int
		// The resulting backoff value should be >= low or <= high
		low  time.Duration
		high time.Duration
	}{
		{
			attempt: 0,
			low:     324 * time.Millisecond,
			high:    524 * time.Millisecond,
		},
		{
			attempt: 1,
			low:     524 * time.Millisecond,
			high:    847 * time.Millisecond,
		},
		{
			attempt: 2,
			low:     847 * time.Millisecond,
			high:    1371 * time.Millisecond,
		},
		{
			attempt: 3,
			low:     1371 * time.Millisecond,
			high:    2218 * time.Millisecond,
		},
		{
			attempt: 4,
			low:     2218 * time.Millisecond,
			high:    3588 * time.Millisecond,
		},
	}

	for _, tc := range tcs {
		t.Run(fmt.Sprintf("attempt %d", tc.attempt), func(t *testing.T) {
			got := exponentialBackoff(tc.attempt)
			got = got.Round(time.Millisecond)
			if got < tc.low {
				t.Fatalf("got was below lower bound, got = %v, want = %v",
					got, tc.low,
				)
			}
			if got > tc.high {
				t.Fatalf("got was above upper bound, got = %v, want = %v",
					got, tc.high,
				)
			}
		})
	}
}

func TestRetry(t *testing.T) {
	tcs := []struct {
		desc      string
		f         func(context.Context) (*any, error)
		wantCount int
	}{
		{
			desc: "unknown errors are not retried",
			f: func(context.Context) (*any, error) {
				return nil, errors.New("unknown")
			},
			wantCount: 0,
		},
		{
			desc: "do not retry non-50x responses",
			f: func(context.Context) (*any, error) {
				return nil, &googleapi.Error{
					Code: 400,
				}
			},
			wantCount: 0,
		},
		{
			desc: "retry >= 500 HTTP responses with wait function",
			f: func(context.Context) (*any, error) {
				return nil, &googleapi.Error{
					Code: 500,
				}
			},
			wantCount: 5,
		},
		{
			desc: "successful response is not retried",
			f: func(context.Context) (*any, error) {
				// no error means success
				return nil, nil
			},
			wantCount: 0,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			var callCount int
			waitSpy := func(int) time.Duration {
				callCount++
				return time.Microsecond
			}

			retry50x(context.Background(), tc.f, waitSpy)

			if callCount != tc.wantCount {
				t.Fatalf(
					"retry call count, want = %v, got = %v",
					tc.wantCount, callCount,
				)
			}
		})
	}
}

func TestRetryExitsEarlyOnContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	fail := func(context.Context) (*any, error) {
		err := &googleapi.Error{
			Code:    500,
			Message: "I always fail",
		}
		return nil, err
	}
	// Context cancellation short-circuits the wait duration
	waitOneHour := func(int) time.Duration { return time.Hour }

	_, err := retry50x(ctx, fail, waitOneHour)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want = %v, got = %v", context.Canceled, err)
	}
}
