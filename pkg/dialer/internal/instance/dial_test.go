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
	"net"
	"testing"

	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

func TestAll(t *testing.T) {
	ctx := context.Background()

	client, err := sqladmin.NewService(ctx)
	if err != nil {
		t.Fatalf("client init failed: %s", err)
	}
	inst, err := parseConnName(instConnName)
	if err != nil {
		t.Fatalf("%s", err)
	}

	// Step 0: Generate Keys
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate keys: %v", err)
	}

	// Step 1a: Fetch Metadata
	m, err := fetchMetadata(ctx, client, inst)
	if err != nil {
		t.Fatalf("failed to fetch metadata: %v", err)
	}

	// Step 1b: Fetch Ephemeral Certificate
	cert, err := fetchEphemeralCert(ctx, client, inst, key)
	if err != nil {
		t.Fatalf("failed to fetch ephemeral cert: %v", err)
	}

	// Step 3: Create TLS config
	cfg := createTLSConfig(inst, m, cert)

	// Step 4: Connect to instance
	addr := net.JoinHostPort(m.ipAddrs["PUBLIC"], "3307")
	conn, err := connect(ctx, addr, cfg)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	conn.Close()
}
