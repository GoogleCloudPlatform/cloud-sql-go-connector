// Copyright 2021 Google LLC

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mock

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

// CloudSQLInst represents settings for a specific Cloud SQL instance.
//
// Use NewCloudSQLInstance to instantiate.
type CloudSQLInst struct {
	project string
	region  string
	name    string

	dbVersion string

	privKey *rsa.PrivateKey
	cert    *x509.Certificate
}

// NewCloudSQLInst returns a CloudSQLInst object for configuring mocks.
func NewCloudSQLInst(project, region, name string) (CloudSQLInst, error) {
	// TODO: consider options for this?
	privKey, cert, err := generateInstanceCerts()
	if err != nil {
		return CloudSQLInst{}, err
	}

	c := CloudSQLInst{
		project:   project,
		region:    region,
		name:      name,
		dbVersion: "POSTGRES_12", // default of no particular importance
		privKey:   privKey,
		cert:      cert,
	}
	return c, nil
}

// generateInstanceCerts returns a key and cert for representing a Cloud SQL instance.
func generateInstanceCerts() (*rsa.PrivateKey, *x509.Certificate, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	cert := &x509.Certificate{
		SerialNumber: &big.Int{},
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Google, Inc"},
			CommonName:   "Google Cloud SQL Server CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, 1),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	return privKey, cert, nil
}
