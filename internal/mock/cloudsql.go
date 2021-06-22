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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// FakeCSQLInstance represents settings for a specific Cloud SQL instance.
//
// Use NewFakeCSQLInstance to instantiate.
type FakeCSQLInstance struct {
	project string
	region  string
	name    string
	version string
	key     *rsa.PrivateKey
	cert    *x509.Certificate
	tlsCert tls.Certificate
}

// NewFakeCSQLInstance returns a CloudSQLInst object for configuring mocks.
func NewFakeCSQLInstance(project, region, name string) FakeCSQLInstance {
	// TODO: consider options for this?
	key, cert, tlsCert, err := generateCerts(project, name)
	if err != nil {
		panic(err)
	}

	return FakeCSQLInstance{
		project: project,
		region:  region,
		name:    name,
		version: "POSTGRES_12", // default of no particular importance
		key:     key,
		cert:    cert,
		tlsCert: tlsCert,
	}
}

// generateCerts generates a private key, an X.509 certificate, and a TLS
// certificate for a particular fake Cloud SQL database instance.
func generateCerts(project, name string) (*rsa.PrivateKey, *x509.Certificate, tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, tls.Certificate{}, err
	}

	cert := &x509.Certificate{
		SerialNumber: &big.Int{},
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("%s:%s", project, name),
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, 1),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(
		rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		return nil, nil, tls.Certificate{}, err
	}

	caPEM := &bytes.Buffer{}
	pem.Encode(caPEM, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	caKeyPEM := &bytes.Buffer{}
	pem.Encode(caKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	serverCert, err := tls.X509KeyPair(caPEM.Bytes(), caKeyPEM.Bytes())
	if err != nil {
		return nil, nil, tls.Certificate{}, err
	}

	return key, cert, serverCert, nil
}

type ServerProxyConfig struct {
	// Response is the value the proxy will write back to the client.
	Response string
	// Instance is the Fake Cloud SQL instance used for TLS configuration.
	Instance FakeCSQLInstance
	// InvalidCert determines if the server proxy should start up with a known
	// bad configuration.
	InvalidCert bool
}

// StartServerProxy starts a fake server proxy and listens on the provided port
// on all interfaces, configured with TLS as specified by the FakeCSQLInstance.
// Callers should invoke the returned function to clean up all resources.
func StartServerProxy(config ServerProxyConfig) func() {
	cert := config.Instance.tlsCert
	if config.InvalidCert {
		cert = tls.Certificate{}
	}
	ln, err := tls.Listen("tcp", ":3307", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		panic(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				conn.Write([]byte(config.Response))
				conn.Close()
			}
		}
	}()
	return func() {
		ln.Close()
		cancel()
	}
}
