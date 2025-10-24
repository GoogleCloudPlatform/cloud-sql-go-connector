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
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
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
	DNSName    string
	MissingSAN string
	DNSNames   []*sqladmin.DnsNameMapping

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

// WithMissingSAN will cause the omit this dns name
// from the server cert, even though it is in the metadata.
func WithMissingSAN(dns string) FakeCSQLInstanceOption {
	return func(f *FakeCSQLInstance) {
		f.MissingSAN = dns
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

// WithServerCaCert sets the ServerCaCert of the instance.
func WithServerCaCert(c *sqladmin.SslCert) FakeCSQLInstanceOption {
	return func(i *FakeCSQLInstance) {
		i.ServerCaCert = c
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
	if f.DNSName != "" && f.DNSName != f.MissingSAN {
		sanNames = append(sanNames, f.DNSName)
	}
	for _, dnm := range f.DNSNames {
		if dnm.Name != f.MissingSAN {
			sanNames = append(sanNames, dnm.Name)
		}
	}
	if len(sanNames) > 0 {
		f.useStandardTLSValidation = true
	}

	certs := NewTLSCertificates(project, name, sanNames, f.certExpiry)

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

				go func(c net.Conn) {
					csqlBytes := make([]byte, 8)
					c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
					_, rErr := c.Read(csqlBytes)
					if errors.Is(err, os.ErrDeadlineExceeded) {
						t.Logf("Read timeout")
					} else if rErr != nil {
						t.Logf("Fake server read error: %v", rErr)
					}
					var res []byte
					if bytes.Compare(csqlBytes, []byte("CSQLMDEX")) == 0 {
						mdxBytes, err := io.ReadAll(c)
						if err != nil {
							t.Logf("Error reading MDX message: %v", err)
						}
						t.Logf("Fake server received metadata exchange request: %v", mdxBytes)

						// This is byte-level equivalent of
						// mdx.MetadataExchangeResponse{Status:OK}
						res = []byte("CSQLMDEX")
						res = append(res, []byte{0x0, 0x0, 0x0, 0x2, 0x8, 0x1}...)
					}
					res = append(res, []byte(i.name)...)
					_, wErr := c.Write(res)
					if wErr != nil {
						t.Logf("Fake server write error: %v", wErr)
					}
					_ = c.Close()
				}(conn)
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

// FailoverTestServer creates a mock server listening on port 3307
// using TLS certificate validation like a real CloudSQL instance.
type FailoverTestServer struct {
	t  *testing.T
	ln net.Listener
	// The cancel function for the accept loop
	cancel func()

	// The context for connections
	connCtx context.Context
	// The cancel function for open connections
	connCancel func()

	activeInstance *FakeCSQLInstance

	readBufLock sync.Mutex
	readBuf     []byte
}

// NewFailoverTestServer creates a new test server.
func NewFailoverTestServer(t *testing.T) *FailoverTestServer {
	connCtx, connCancelFn := context.WithCancel(context.Background())
	return &FailoverTestServer{
		t:          t,
		connCtx:    connCtx,
		connCancel: connCancelFn,
	}
}

// Start starts the test server up, to make sure that it is ready to go
func (s *FailoverTestServer) Start(i *FakeCSQLInstance) {

	ln, err := tls.Listen("tcp", ":3307", &tls.Config{
		Certificates: i.certs.serverChain(i.useStandardTLSValidation),
		ClientCAs:    i.certs.clientCAPool(),
		ClientAuth:   tls.RequireAndVerifyClientCert,
	})
	if err != nil {
		s.t.Fatalf("failed to start listener: %v", err)
	}
	ctx, cancelFn := context.WithCancel(context.Background())

	s.ln = ln
	s.cancel = cancelFn
	s.activeInstance = i
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
					s.t.Logf("Fake server accept error: %v", aErr)
					return
				}
				go s.handleConnection(conn)
			}
		}
	}()
}

// Stop closes the server socket, but leaves existing client sockets open.
func (s *FailoverTestServer) Stop() {
	s.cancel()
	_ = s.ln.Close()
	s.activeInstance = nil
}

// Close closes the server socket and client sockets.
func (s *FailoverTestServer) Close() {
	s.Stop()
	s.connCancel()
}

// handleConnection handles a single client socket.
func (s *FailoverTestServer) handleConnection(conn net.Conn) {
	s.t.Logf("server: handled connection")
	defer conn.Close()
	r := bufio.NewReader(conn)
	nameAtStart := s.activeInstance.name
	for {
		select {
		case <-s.connCtx.Done():
			s.t.Logf("server %v: context done", nameAtStart)
			return
		default:

			l, _, rErr := r.ReadLine()
			if rErr == io.EOF {
				return
			}
			s.readBufLock.Lock()
			s.readBuf = append(s.readBuf, l...)
			s.readBufLock.Unlock()

			var nameNow string
			if s.activeInstance != nil {
				nameNow = s.activeInstance.name
			}

			_, wErr := conn.Write([]byte(nameNow + "\n"))
			if wErr != nil {
				s.t.Logf("server: write error: %v", wErr)
				return
			}
			s.t.Logf("server: handled read, %v", string(l))
		}
	}
}

// DbClient represents an open connection to the FailoverTestServer.
// it sends a message every 2 seconds and reads the response until
// Close() is called.
type DbClient struct {
	// The Id of this client for debugging ease
	id string
	// This channel is open until
	C chan struct{}
	// The connection that the dialer created
	conn net.Conn
	//
	t          *testing.T
	serverName string
	mu         sync.Mutex
	closed     bool
	readCount  int
	recv       []string
}

// NewDbClient creates a new client that sends and receives data from the
// conn.
func NewDbClient(t *testing.T, conn net.Conn, id string) *DbClient {
	return &DbClient{
		id:   id,
		t:    t,
		conn: conn,
		C:    make(chan struct{}),
	}
}

// Execute runs the loop to send and receive data from the client. This will
// stop when ctx Context is canceled.
func (c *DbClient) Execute(ctx context.Context) {
	c.t.Logf("client %v: Starting", c.id)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	defer c.Close()
	r := bufio.NewReader(c.conn)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.t.Logf("client %v: writing hello", c.id)
			c.conn.Write([]byte(fmt.Sprintf("hello %s\n", c.id)))
			data, _, err := r.ReadLine()
			if err == io.EOF {
				c.t.Logf("client %v: Connection closed", c.id)
				return
			}
			if err != nil {
				c.t.Logf("client %v: error %v", c.id, err)
				return
			}
			c.mu.Lock()
			c.readCount++
			c.recv = append(c.recv, string(data))
			c.mu.Unlock()
			c.t.Logf("client %v: received %v", c.id, string(data))
		}
	}
}

// Close stops the send-receive loop and closes the socket.
func (c *DbClient) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.t.Logf("client %v: Closing", c.id)
	c.conn.Close()
	close(c.C)
	c.closed = true
	c.mu.Unlock()
}

// Closed reports whether the client has been closed.
func (c *DbClient) Closed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// Recv returns a copy of the messages received by the client.
func (c *DbClient) Recv() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	r := make([]string, len(c.recv))
	copy(r, c.recv)
	return r
}
