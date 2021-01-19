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
	"crypto/rand"
	"crypto/rsa"
	"os"
	"testing"

	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

var (
	instConnName = os.Getenv("INSTANCE_CONNECTION_NAME")
)

func TestParseConnName(t *testing.T) {
	tests := []struct {
		name string
		want connName
	}{
		{
			"project:region:instance",
			connName{"project", "region", "instance"},
		},
		{
			"google.com:project:region:instance",
			connName{"google.com:project", "region", "instance"},
		},
		{
			"project:instance",
			connName{},
		},
	}

	for _, tc := range tests {
		c, err := parseConnName(tc.name)
		if err != nil && tc.want != (connName{}) {
			t.Errorf("unexpected error: %e", err)
		}
		if c != tc.want {
			t.Errorf("ParseConnName(%s) failed: want %v, got %v", tc.name, tc.want, err)
		}
	}
}

func TestConnect(t *testing.T) {
	ctx := context.Background()

	client, err := sqladmin.NewService(ctx)
	if err != nil {
		t.Fatalf("client init failed: %s", err)
	}

	// Step 0: Generate Keys
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate keys: %v", err)
	}

	im, err := NewInstanceManager(instConnName, client, key)
	if err != nil {
		t.Fatalf("failed to initialize Instance Manager: %v", err)
	}

	conn, err := im.Connect(ctx)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	conn.Close()
}
