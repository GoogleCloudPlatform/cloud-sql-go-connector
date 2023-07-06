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
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// EmptyTokenSource is an Oauth2.TokenSource that returns empty tokens.
type EmptyTokenSource struct{}

// Token provides an empty oauth2.Token.
func (EmptyTokenSource) Token() (*oauth2.Token, error) {
	return &oauth2.Token{Expiry: time.Now().Add(time.Hour)}, nil
}

// FakeCSQLInstance represents settings for a specific Cloud SQL instance.
//
// Use NewFakeCSQLInstance to instantiate.
type FakeCSQLInstance struct {
	project   string
	region    string
	name      string
	dbVersion string
	// ipAddrs is a map of IP type (PUBLIC or PRIVATE) to IP address.
	ipAddrs      map[string]string
	backendType  string
	DNSName      string
	signer       SignFunc
	clientSigner ClientSignFunc
	Key          *rsa.PrivateKey
	Cert         *x509.Certificate
}

func (f FakeCSQLInstance) signedCert() ([]byte, error) {
	return f.signer(f.Cert, f.Key)
}

func (f FakeCSQLInstance) clientCert(pubKey *rsa.PublicKey) ([]byte, error) {
	return f.clientSigner(f.Cert, f.Key, pubKey)
}

// FakeCSQLInstanceOption is a function that configures a FakeCSQLInstance.
type FakeCSQLInstanceOption func(f *FakeCSQLInstance)

// WithPublicIP sets the public IP address to addr.
func WithPublicIP(addr string) FakeCSQLInstanceOption {
	return func(f *FakeCSQLInstance) {
		f.ipAddrs["PUBLIC"] = addr
	}
}

// WithPrivateIP sets the private IP address to addr.
func WithPrivateIP(addr string) FakeCSQLInstanceOption {
	return func(f *FakeCSQLInstance) {
		f.ipAddrs["PRIVATE"] = addr
	}
}

// WithPSC sets the PSC DnsName to addr.
func WithPSC(dns string) FakeCSQLInstanceOption {
	return func(f *FakeCSQLInstance) {
		f.DNSName = dns
	}
}

// WithCertExpiry sets the server certificate's expiration to t.
func WithCertExpiry(t time.Time) FakeCSQLInstanceOption {
	return func(f *FakeCSQLInstance) {
		f.Cert.NotAfter = t
	}
}

// WithRegion sets the server's region to the provided value.
func WithRegion(region string) FakeCSQLInstanceOption {
	return func(f *FakeCSQLInstance) {
		f.region = region
	}
}

// WithFirstGenBackend sets the server backend type to FIRST_GEN.
func WithFirstGenBackend() FakeCSQLInstanceOption {
	return func(f *FakeCSQLInstance) {
		f.backendType = "FIRST_GEN"
	}
}

// WithEngineVersion sets the "DB Version"
func WithEngineVersion(s string) FakeCSQLInstanceOption {
	return func(f *FakeCSQLInstance) {
		f.dbVersion = s
	}
}

// SignFunc is a function that signs the certificate using the provided key. The
// result should be PEM-encoded.
type SignFunc = func(*x509.Certificate, *rsa.PrivateKey) ([]byte, error)

// WithCertSigner configures the signing function used to generate a signed
// certificate.
func WithCertSigner(s SignFunc) FakeCSQLInstanceOption {
	return func(f *FakeCSQLInstance) {
		f.signer = s
	}
}

// ClientSignFunc is a function that produces a certificate signed using the
// provided certificate, using the server's private key and the client's public
// key. The result should be PEM-encoded.
type ClientSignFunc = func(*x509.Certificate, *rsa.PrivateKey, *rsa.PublicKey) ([]byte, error)

// WithClientCertSigner configures the signing function used to generate a
// certificate signed with the client's public key.
func WithClientCertSigner(s ClientSignFunc) FakeCSQLInstanceOption {
	return func(f *FakeCSQLInstance) {
		f.clientSigner = s
	}
}

// WithNoIPAddrs configures a Fake Cloud SQL instance to have no IP
// addresses.
func WithNoIPAddrs() FakeCSQLInstanceOption {
	return func(f *FakeCSQLInstance) {
		f.ipAddrs = map[string]string{}
	}
}

// NewFakeCSQLInstance returns a CloudSQLInst object for configuring mocks.
func NewFakeCSQLInstance(project, region, name string, opts ...FakeCSQLInstanceOption) FakeCSQLInstance {
	// TODO: consider options for this?
	key, cert, err := generateCerts(project, name)
	if err != nil {
		panic(err)
	}

	f := FakeCSQLInstance{
		project:      project,
		region:       region,
		name:         name,
		ipAddrs:      map[string]string{"PUBLIC": "0.0.0.0"},
		DNSName:      "",
		dbVersion:    "POSTGRES_12", // default of no particular importance
		backendType:  "SECOND_GEN",
		signer:       SelfSign,
		clientSigner: SignWithClientKey,
		Key:          key,
		Cert:         cert,
	}
	for _, o := range opts {
		o(&f)
	}
	return f
}

// SelfSign produces a PEM encoded certificate that is self-signed.
func SelfSign(c *x509.Certificate, k *rsa.PrivateKey) ([]byte, error) {
	certBytes, err := x509.CreateCertificate(rand.Reader, c, c, &k.PublicKey, k)
	if err != nil {
		return nil, err
	}
	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return nil, err
	}
	return certPEM.Bytes(), nil
}

// SignWithClientKey produces a PEM encoded certificate signed by the parent
// certificate c using the server's private key and the client's public key.
func SignWithClientKey(c *x509.Certificate, k *rsa.PrivateKey, clientKey *rsa.PublicKey) ([]byte, error) {
	// Create a signed cert from the client's public key.
	cert := &x509.Certificate{ // TODO: Validate this format vs API
		SerialNumber: &big.Int{},
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Google, Inc"},
			CommonName:   "Google Cloud SQL Client",
		},
		NotBefore:             time.Now(),
		NotAfter:              c.NotAfter,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, c, clientKey, k)
	if err != nil {
		return nil, err
	}
	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return nil, err
	}
	return certPEM.Bytes(), nil
}

// GenerateCertWithCommonName produces a certificate signed by the Fake Cloud
// SQL instance's CA with the specified common name cn.
func GenerateCertWithCommonName(i FakeCSQLInstance, cn string) []byte {
	cert := &x509.Certificate{
		SerialNumber: &big.Int{},
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 0, 1),
		IsCA:      true,
	}
	signed, err := x509.CreateCertificate(
		rand.Reader, cert, i.Cert, &i.Key.PublicKey, i.Key)
	if err != nil {
		panic(err)
	}
	return signed
}

// generateCerts generates a private key, an X.509 certificate, and a TLS
// certificate for a particular fake Cloud SQL database instance.
func generateCerts(project, name string) (*rsa.PrivateKey, *x509.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
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

	return key, cert, nil
}

// StartServerProxy starts a fake server proxy and listens on the provided port
// on all interfaces, configured with TLS as specified by the FakeCSQLInstance.
// Callers should invoke the returned function to clean up all resources.
func StartServerProxy(t *testing.T, i FakeCSQLInstance) func() {
	certBytes, err := x509.CreateCertificate(
		rand.Reader, i.Cert, i.Cert, &i.Key.PublicKey, i.Key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	caPEM := &bytes.Buffer{}
	err = pem.Encode(caPEM, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		t.Fatalf("pem.Encode: %v", err)
	}

	caKeyPEM := &bytes.Buffer{}
	err = pem.Encode(caKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(i.Key),
	})
	if err != nil {
		t.Fatalf("pem.Encode: %v", err)
	}

	serverCert, err := tls.X509KeyPair(caPEM.Bytes(), caKeyPEM.Bytes())
	if err != nil {
		t.Fatalf("failed to create X.509 Key Pair: %v", err)
	}
	ln, err := tls.Listen("tcp", ":3307", &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	})
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
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
				_, _ = conn.Write([]byte(i.name))
				_ = conn.Close()
			}
		}
	}()
	return func() {
		cancel()
		_ = ln.Close()
	}
}
