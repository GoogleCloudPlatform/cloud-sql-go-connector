// Copyright 2020 Google LLC

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package instance

import (
	"context"
	"testing"

	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

func TestFetchMetadata(t *testing.T) {
	ctx := context.Background()
	client, err := sqladmin.NewService(ctx)
	if err != nil {
		t.Fatalf("client init failed: %s", err)
	}

	cn, err := parseConnName(instConnName)
	if err != nil {
		t.Fatalf("%s", err)
	}

	_, err = fetchMetadata(ctx, client, cn)
	if err != nil {
		t.Fatalf("%s", err)
	}
}
