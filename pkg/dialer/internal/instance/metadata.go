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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

// metadata contains basic information about the instance required to connect
type metadata struct {
	ipAddrs      map[string]string
	serverCaCert *x509.Certificate
	version      string
}

// fetchMetadata makes sqladmin API call to instances.get to gather metadata about an instance
func fetchMetadata(ctx context.Context, client *sqladmin.Service, inst connName) (metadata, error) {
	db, err := client.Instances.Get(inst.project, inst.name).Context(ctx).Do()
	if err != nil {
		return metadata{}, fmt.Errorf("failed to get instance (%s): %w", inst, err)
	}

	// validate the instance is supported for authenticated connections
	if db.Region != inst.region {
		return metadata{}, fmt.Errorf("provided region was mismatched - got %s, want %s", inst.region, db.Region)
	}
	if db.BackendType != "SECOND_GEN" {
		return metadata{}, fmt.Errorf("unsupported instance - only Second Generation instances are supported")
	}

	// parse any ip addresses that might be used to connect
	ipAddrs := make(map[string]string)
	for _, ip := range db.IpAddresses {
		switch ip.Type {
		case "PRIMARY":
			ipAddrs["PUBLIC"] = ip.IpAddress
		case "PRIVATE":
			ipAddrs["PRIVATE"] = ip.IpAddress
		}
	}
	if len(ipAddrs) == 0 {
		return metadata{}, fmt.Errorf("unsupported instance - contains no valid ip addresses")
	}

	// parse the server-side CA certificate
	b, _ := pem.Decode([]byte(db.ServerCaCert.Cert))
	if b == nil {
		return metadata{}, errors.New("failed to decode valid PEM cert")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return metadata{}, fmt.Errorf("failed to parse as x509 cert: %s", err)
	}

	return metadata{ipAddrs, cert, db.DatabaseVersion}, nil
}
