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
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)


func fetchEphemeralCert(ctx context.Context, client *sqladmin.Service, inst connName, key *rsa.PrivateKey)  (tls.Certificate, error) {
	clientPubKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	req := sqladmin.SslCertsCreateEphemeralRequest{
		PublicKey: string(pem.EncodeToMemory(&pem.Block{Bytes: clientPubKey, Type: "RSA PUBLIC KEY"})),
	}
	resp, err := client.SslCerts.CreateEphemeral(inst.project, inst.name, &req).Context(ctx).Do()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create ephemeral failed: %w", err)
	}

	// parse the client cert
	b, _ := pem.Decode([]byte(resp.Cert))
	if b == nil {
		return tls.Certificate{}, errors.New("failed to decode valid PEM cert")
	}
	clientCert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to parse as x509 cert: %s", err)
	}

	tmpCert := tls.Certificate{
		Certificate: [][]byte{clientCert.Raw},
		PrivateKey: key,
		Leaf: clientCert,
	}
	return tmpCert, nil
}
