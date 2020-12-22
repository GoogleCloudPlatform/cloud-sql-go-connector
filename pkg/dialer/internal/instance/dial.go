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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/proxy"
)


func connect(ctx context.Context, addr string, cfg *tls.Config) (net.Conn, error) {
	conn, err := proxy.Dial(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if c, ok := conn.(*net.TCPConn); ok {
		if err := c.SetKeepAlive(true); err != nil{
			return nil, fmt.Errorf("failed to set keep-alive: %w", err)
		}
		if err := c.SetKeepAlivePeriod(30 * time.Second); err != nil{
			return nil, fmt.Errorf("failed to set keep-alive period: %w", err)
		}
	}

	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("handshake failed: %w", err)
	}
	return tlsConn, err
}


func createTLSConfig(inst connName, m metadata, cert tls.Certificate) *tls.Config {
	certs := x509.NewCertPool()
	certs.AddCert(m.serverCaCert)

	cfg := &tls.Config{
		ServerName:   inst.String(),
		Certificates: []tls.Certificate{cert},
		RootCAs:      certs,
		// We need to set InsecureSkipVerify to true due to
		// https://github.com/GoogleCloudPlatform/cloudsql-proxy/issues/194
		// https://tip.golang.org/doc/go1.11#crypto/x509
		//
		// Since we have a secure channel to the Cloud SQL API which we use to retrieve the
		// certificates, we instead need to implement our own VerifyPeerCertificate function
		// that will verify that the certificate is OK.
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: genVerifyPeerCertificateFunc(inst, certs),
	}
	return cfg
}


// genVerifyPeerCertificateFunc creates a VerifyPeerCertificate func that verifies that the peer
// certificate is in the cert pool. We need to define our own because of our sketchy non-standard
// CNs.
func genVerifyPeerCertificateFunc(cn connName, pool *x509.CertPool) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no certificate to verify")
		}

		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("x509.ParseCertificate(rawCerts[0]) returned error: %v", err)
		}

		opts := x509.VerifyOptions{Roots: pool}
		if _, err = cert.Verify(opts); err != nil {
			return err
		}

		certInstanceName := cn.project + ":" + cn.name
		if cert.Subject.CommonName != certInstanceName {
			return fmt.Errorf("certificate had CN %q, expected %q", cert.Subject.CommonName, certInstanceName)
		}
		return nil
	}
}