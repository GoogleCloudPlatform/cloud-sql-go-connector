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
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"cloud.google.com/go/cloudsqlconn/internal/connectorspb"
	"golang.org/x/oauth2"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
	"google.golang.org/protobuf/proto"
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
	ipAddrs     map[string]string
	backendType string

	// DNSName is the legacy field
	// DNSNames supersedes DNSName.
	DNSName  string
	DNSNames []*sqladmin.DnsNameMapping

	useStandardTLSValidation bool
	serverCAMode             string
	pscEnabled               bool
	signer                   SignFunc
	clientSigner             ClientSignFunc
	certExpiry               time.Time
	// Key is the server's private key
	Key *rsa.PrivateKey
	// Cert is the server's certificate
	Cert *x509.Certificate
	// certs holds all of the certificates for this instance
	certs *TLSCertificates
}

// String returns the instance connection name for the
// instance.
func (f FakeCSQLInstance) String() string {
	return fmt.Sprintf("%v:%v:%v", f.project, f.region, f.name)
}

// serverCACert returns the current server CA cert.
func (f FakeCSQLInstance) serverCACert() ([]byte, error) {
	if f.signer != nil {
		return f.signer(f.Cert, f.Key)
	}
	if !f.useStandardTLSValidation {
		// legacy server mode, return only the server cert
		return toPEMFormat(f.certs.serverCert)
	}
	return toPEMFormat(f.certs.casServerCertificate, f.certs.serverIntermediateCaCert, f.certs.serverCaCert)
}

// ClientCert creates an ephemeral client certificate signed with the Cloud SQL
// instance's private key. The return value is PEM encoded.
func (f FakeCSQLInstance) ClientCert(pubKey *rsa.PublicKey) ([]byte, error) {
	if f.clientSigner != nil {
		c, err := f.clientSigner(f.Cert, f.Key, pubKey)
		if err != nil {
			return c, err
		}
		return c, nil
	}
	return f.certs.signWithClientKey(pubKey)
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

// WithPSC sets the PSC enabled.
func WithPSC(enabled bool) FakeCSQLInstanceOption {
	return func(f *FakeCSQLInstance) {
		f.pscEnabled = enabled
	}
}

// WithDNS sets the DnsName to addr.
func WithDNS(dns string) FakeCSQLInstanceOption {
	return func(f *FakeCSQLInstance) {
		f.DNSName = dns
	}
}

// WithDNSMapping adds the DnsNames records
func WithDNSMapping(name, dnsScope, connectionType string) FakeCSQLInstanceOption {
	return func(f *FakeCSQLInstance) {
		f.DNSNames = append(f.DNSNames,
			&sqladmin.DnsNameMapping{
				Name:           name,
				DnsScope:       dnsScope,
				ConnectionType: connectionType})
	}
}

// WithCertExpiry sets the server certificate's expiration to t.
func WithCertExpiry(t time.Time) FakeCSQLInstanceOption {
	return func(f *FakeCSQLInstance) {
		f.certExpiry = t
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

// WithServerCAMode sets the ServerCaMode of the instance.
func WithServerCAMode(serverCAMode string) FakeCSQLInstanceOption {
	return func(f *FakeCSQLInstance) {
		f.serverCAMode = serverCAMode
	}
}

// NewFakeCSQLInstance returns a CloudSQLInst object for configuring mocks.
func NewFakeCSQLInstance(project, region, name string, opts ...FakeCSQLInstanceOption) FakeCSQLInstance {

	f := FakeCSQLInstance{
		project:     project,
		region:      region,
		name:        name,
		ipAddrs:     map[string]string{"PUBLIC": "0.0.0.0"},
		DNSName:     "",
		dbVersion:   "POSTGRES_12", // default of no particular importance
		backendType: "SECOND_GEN",
	}
	for _, o := range opts {
		o(&f)
	}
	sanNames := make([]string, 0, 5)
	if f.DNSName != "" {
		sanNames = append(sanNames, f.DNSName)
	}
	for _, dnm := range f.DNSNames {
		sanNames = append(sanNames, dnm.Name)
	}
	if len(sanNames) > 0 {
		f.useStandardTLSValidation = true
	}

	certs := newTLSCertificates(project, name, sanNames, f.certExpiry)

	f.Key = certs.serverKey
	f.Cert = certs.serverCert
	f.certs = certs

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

// GenerateCertWithCommonName produces a certificate signed by the Fake Cloud
// SQL instance's CA with the specified common name cn.
func GenerateCertWithCommonName(i FakeCSQLInstance, cn string) []byte {
	return i.certs.generateServerCertWithCn(cn).Raw
}

// StartServerProxy starts a fake server proxy and listens on the provided port
// on all interfaces, configured with TLS as specified by the FakeCSQLInstance.
// Callers should invoke the returned function to clean up all resources.
func StartServerProxy(t *testing.T, i FakeCSQLInstance) func() {

	ln, err := tls.Listen("tcp", ":3307", &tls.Config{
		Certificates: i.certs.serverChain(i.useStandardTLSValidation),
		ClientCAs:    i.certs.clientCAPool(),
		ClientAuth:   tls.RequireAndVerifyClientCert,
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
				conn, aErr := ln.Accept()
				if opErr, ok := aErr.(net.Error); ok {
					if opErr.Timeout() {
						continue
					}
					return
				}
				if aErr == io.EOF {
					return
				}
				if aErr != nil {
					t.Logf("Fake server accept error: %v", aErr)
					return
				}
				if aErr := metadataExchange(conn); aErr != nil {
					conn.Close()
					return
				}

				// Database protocol takes over from here.
				_, wErr := conn.Write([]byte(i.name))
				if wErr != nil {
					t.Logf("Fake server write error: %v", wErr)
				}
				_ = conn.Close()
			}
		}
	}()
	return func() {
		cancel()
		_ = ln.Close()
	}
}

// RotateCA rotates all CA certificates and keys.
func RotateCA(inst FakeCSQLInstance) {
	inst.certs.rotateCA()
}

// RotateClientCA rotates only client CA certificates and keys.
func RotateClientCA(inst FakeCSQLInstance) {
	inst.certs.rotateClientCA()
}

// metadataExchange mimics server side behavior in four steps:
//
//  1. Read a big endian uint32 (4 bytes) from the client. This is the number of
//     bytes the message consumes. The length does not include the initial four
//     bytes.
//
//  2. Read the message from the client using the message length and unmarshal
//     it into a MetadataExchangeResponse message.
//
//  3. Prepare a response and write the size of the response as a uint32 (4
//     bytes)
//
// 4. Marshal the response to bytes and write those to the client as well.
//
// Subsequent interactions with the test server use the database protocol.
func metadataExchange(conn net.Conn) error {
	msgSize := make([]byte, 4)
	n, err := conn.Read(msgSize)
	if err != nil {
		return err
	}
	if n != 4 {
		return fmt.Errorf("read %d bytes, want = 4", n)
	}

	size := binary.BigEndian.Uint32(msgSize)
	buf := make([]byte, size)
	n, err = conn.Read(buf)
	if err != nil {
		return err
	}
	if n != int(size) {
		return fmt.Errorf("read %d bytes, want = %d", n, size)
	}

	m := &connectorspb.MetadataExchangeRequest{}
	err = proto.Unmarshal(buf, m)
	if err != nil {
		return err
	}

	resp := &connectorspb.MetadataExchangeResponse{
		ResponseCode: connectorspb.MetadataExchangeResponse_OK,
	}
	data, err := proto.Marshal(resp)
	if err != nil {
		return err
	}
	respSize := proto.Size(resp)
	buf = make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(respSize))

	buf = append(buf, data...)
	n, err = conn.Write(buf)
	if err != nil {
		return err
	}
	if n != len(buf) {
		return fmt.Errorf("write %d bytes, want = %d", n, len(buf))
	}
	return nil
}
