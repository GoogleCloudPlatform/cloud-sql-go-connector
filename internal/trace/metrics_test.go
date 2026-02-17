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

package trace //nolint:revive

import (
	"errors"
	"fmt"
	"testing"

	"google.golang.org/api/googleapi"
)

func TestMetricsInitializes(t *testing.T) {
	if err := InitMetrics(); err != nil {
		t.Fatalf("want no error, got = %v", err)
	}
}

func TestErrorCodes(t *testing.T) {
	tcs := []struct {
		desc string
		in   error
		want string
	}{
		{
			desc: "without an API error",
			in:   errors.New("not an API error"),
			want: "",
		},
		{
			desc: "with a single API error",
			in: fmt.Errorf("outer: %w", &googleapi.Error{
				Errors: []googleapi.ErrorItem{
					{Reason: "instanceDoesNotExist"},
				},
			}),
			want: "instanceDoesNotExist",
		},
		{
			desc: "with multiple API errors",
			in: fmt.Errorf("outer: %w", &googleapi.Error{
				Errors: []googleapi.ErrorItem{
					{Reason: "instanceDoesNotExist"},
					{Reason: "someOtherError"},
				},
			}),
			want: "instanceDoesNotExist,someOtherError",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			if got := errorCode(tc.in); got != tc.want {
				t.Errorf("want = %v, got = %v", got, tc.want)
			}
		})
	}
}
