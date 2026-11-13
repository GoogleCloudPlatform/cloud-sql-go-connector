// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cloudsql

import (
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
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/cloudsqlconn/errtype"
	"cloud.google.com/go/cloudsqlconn/instance"
	"cloud.google.com/go/cloudsqlconn/internal/mock"
	"github.com/jackc/pgx/v5/pgproto3"
	"google.golang.org/api/option"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
	"net/http"
	"net/http/httptest"
)

type nullLogger struct{}

func (nullLogger) Debugf(context.Context, string, ...interface{}) {}

// genRSAKey generates an RSA key used for test.
func genRSAKey() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err) // unexpected, so just panic if it happens
	}
	return key
}

func testInstanceConnName() instance.ConnName {
	cn, _ := instance.ParseConnName("my-project:my-region:my-instance")
	return cn
}

// RSAKey is used for test only.
var RSAKey = genRSAKey()

func TestConnectionInfoDBVersion(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tests := []string{
		"MYSQL_5_7", "POSTGRES_14", "SQLSERVER_2019_STANDARD", "MYSQL_8_0_18",
	}
	for _, wantEV := range tests {
		inst := mock.NewFakeCSQLInstance("my-project", "my-region", "my-instance", mock.WithEngineVersion(wantEV))
		client, cleanup, err := mock.NewSQLAdminService(
			ctx,
			mock.InstanceGetSuccess(inst, 1),
			mock.CreateEphemeralSuccess(inst, 1),
		)
		if err != nil {
			t.Fatalf("%s", err)
		}
		defer func() {
			if err := cleanup(); err != nil {
				t.Fatalf("%v", err)
			}
		}()
		i := NewRefreshAheadCache(
			testInstanceConnName(), nullLogger{}, client,
			RSAKey, 30*time.Second, nil, "", false, nil,
		)
		if err != nil {
			t.Fatalf("failed to init instance: %v", err)
		}

		ci, err := i.ConnectionInfo(ctx)
		if err != nil {
			t.Fatalf("failed to retrieve engine version: %v", err)
		}
		if wantEV != ci.DBVersion {
			t.Errorf("ConnectionInfo(%s) failed: want %v, got %v", wantEV, ci, err)
		}

	}
}

func TestConnectionInfo(t *testing.T) {
	ctx := context.Background()
	wantAddr := "0.0.0.0"
	inst := mock.NewFakeCSQLInstance(
		"my-project", "my-region", "my-instance", mock.WithPublicIP(wantAddr),
	)
	client, cleanup, err := mock.NewSQLAdminService(
		ctx,
		mock.InstanceGetSuccess(inst, 1),
		mock.CreateEphemeralSuccess(inst, 1),
	)
	if err != nil {
		t.Fatalf("%s", err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			t.Fatalf("%v", err)
		}
	}()

	i := NewRefreshAheadCache(
		testInstanceConnName(), nullLogger{}, client,
		RSAKey, 30*time.Second, nil, "", false, nil,
	)

	ci, err := i.ConnectionInfo(ctx)
	if err != nil {
		t.Fatalf("failed to retrieve connect info: %v", err)
	}

	got, err := ci.Addr(PublicIP)
	if err != nil {
		t.Fatal(err)
	}
	if got != wantAddr {
		t.Fatalf(
			"ConnectInfo returned unexpected IP address, want = %v, got = %v",
			wantAddr, got,
		)
	}
}

func TestConnectionInfoTLSConfig(t *testing.T) {
	cn := testInstanceConnName()
	i := mock.NewFakeCSQLInstance(cn.Project(), cn.Region(), cn.Name())
	// Generate a client certificate with the client's public key and signed by
	// the server's private key
	cert, err := i.ClientCert(&RSAKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	// Now parse the bytes back out as structured data
	// TODO: this should be done in the ClientCert method and not here.
	b, _ := pem.Decode(cert)
	clientCert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	// Assemble a connection info with the raw and parsed client cert
	// and the self-signed server certificate
	ci := ConnectionInfo{
		ConnectionName: cn,
		ClientCertificate: tls.Certificate{
			Certificate: [][]byte{clientCert.Raw},
			PrivateKey:  RSAKey,
			Leaf:        clientCert,
		},
		ServerCACert: []*x509.Certificate{i.Cert},
		DBVersion:    "doesn't matter here",
		Expiration:   clientCert.NotAfter,
	}

	got := ci.TLSConfig()

	if got.MinVersion != tls.VersionTLS13 {
		t.Fatalf(
			"want CLIENT_PROTOCOL_TLS 1.3, got = %v", got.MinVersion,
		)
	}

	if len(got.CurvePreferences) != 0 {
		t.Fatalf(
			"want empty CurvePreferences so crypto/tls uses default post-quantum key exchange (X25519MLKEM768), got = %v",
			got.CurvePreferences,
		)
	}

	if got.Certificates[0].Leaf != ci.ClientCertificate.Leaf {
		t.Fatal("leaf certificates do not match")
	}

	verifyPeerCert := got.VerifyPeerCertificate
	err = verifyPeerCert([][]byte{i.Cert.Raw}, nil)
	if err != nil {
		t.Fatalf("expected to verify peer cert, got error: %v", err)
	}

	err = verifyPeerCert(nil, nil)
	var wantErr *errtype.DialError
	if !errors.As(err, &wantErr) {
		t.Fatalf(
			"when verify peer cert fails, want = %T, got = %v", wantErr, err,
		)
	}

	// Ensure invalid certs result in an error
	err = verifyPeerCert([][]byte{[]byte("not a cert")}, nil)
	if !errors.As(err, &wantErr) {
		t.Fatalf(
			"when verify fails on invalid cert, want = %T, got = %v",
			wantErr, err,
		)
	}

	// Ensure the common name is verified againsts the expected name
	badCert := mock.GenerateCertWithCommonName(i, "wrong:wrong")
	err = verifyPeerCert([][]byte{badCert}, nil)
	if !errors.As(err, &wantErr) {
		t.Fatalf(
			"when common names mismatch, want = %T, got = %v", wantErr, err,
		)
	}

	// Verify an unreconigzed authority is rejected
	other := mock.NewFakeCSQLInstance(cn.Project(), cn.Region(), cn.Name())
	cert, err = mock.SelfSign(other.Cert, other.Key)
	if err != nil {
		t.Fatalf("failed to sign certificate: %v", err)
	}
	b, _ = pem.Decode(cert)
	err = verifyPeerCert([][]byte{b.Bytes}, nil)
	if !errors.As(err, &wantErr) {
		t.Fatalf("when certification fails, want = %T, got = %v", wantErr, err)
	}
}

func TestConnectInfoAutoIP(t *testing.T) {
	tcs := []struct {
		desc   string
		ips    []mock.FakeCSQLInstanceOption
		wantIP string
	}{
		{
			desc: "when public IP is enabled",
			ips: []mock.FakeCSQLInstanceOption{
				mock.WithPublicIP("8.8.8.8"),
				mock.WithPrivateIP("10.0.0.1"),
			},
			wantIP: "8.8.8.8",
		},
		{
			desc: "when only private IP is enabled",
			ips: []mock.FakeCSQLInstanceOption{
				mock.WithPrivateIP("10.0.0.1"),
			},
			wantIP: "10.0.0.1",
		},
	}

	for _, tc := range tcs {
		var opts []mock.FakeCSQLInstanceOption
		opts = append(opts, mock.WithNoIPAddrs())
		opts = append(opts, tc.ips...)
		inst := mock.NewFakeCSQLInstance("my-project", "my-region", "my-instance", opts...)
		client, cleanup, err := mock.NewSQLAdminService(
			context.Background(),
			mock.InstanceGetSuccess(inst, 1),
			mock.CreateEphemeralSuccess(inst, 1),
		)
		if err != nil {
			t.Fatalf("%s", err)
		}
		defer func() {
			if cErr := cleanup(); cErr != nil {
				t.Fatalf("%v", cErr)
			}
		}()

		i := NewRefreshAheadCache(
			testInstanceConnName(), nullLogger{}, client,
			RSAKey, 30*time.Second, nil, "", false, nil,
		)
		if err != nil {
			t.Fatalf("failed to create mock instance: %v", err)
		}

		ci, err := i.ConnectionInfo(context.Background())
		if err != nil {
			t.Fatalf("failed to retrieve connect info: %v", err)
		}

		got, err := ci.Addr(AutoIP)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.wantIP {
			t.Fatalf(
				"ConnectInfo returned unexpected IP address, want = %v, got = %v",
				tc.wantIP, got,
			)
		}
	}
}

func TestConnectInfoSQLDataFallbackIP(t *testing.T) {
	tcs := []struct {
		desc   string
		ips    []mock.FakeCSQLInstanceOption
		wantIP string
	}{
		{
			desc: "when private, psc, and public are all enabled, prefer private",
			ips: []mock.FakeCSQLInstanceOption{
				mock.WithPublicIP("8.8.8.8"),
				mock.WithPrivateIP("10.0.0.1"),
				mock.WithPSC(true),
				mock.WithDNS("abcde.12345.my-region.sql.goog"),
			},
			wantIP: "10.0.0.1",
		},
		{
			desc: "when psc and public are enabled, prefer psc",
			ips: []mock.FakeCSQLInstanceOption{
				mock.WithPublicIP("8.8.8.8"),
				mock.WithPSC(true),
				mock.WithDNS("abcde.12345.my-region.sql.goog"),
			},
			wantIP: "abcde.12345.my-region.sql.goog",
		},
		{
			desc: "when only public IP is enabled, choose public",
			ips: []mock.FakeCSQLInstanceOption{
				mock.WithPublicIP("8.8.8.8"),
			},
			wantIP: "8.8.8.8",
		},
		{
			desc: "when only private IP is enabled, choose private",
			ips: []mock.FakeCSQLInstanceOption{
				mock.WithPrivateIP("10.0.0.1"),
			},
			wantIP: "10.0.0.1",
		},
		{
			desc: "when only psc is enabled, choose psc",
			ips: []mock.FakeCSQLInstanceOption{
				mock.WithPSC(true),
				mock.WithDNS("abcde.12345.my-region.sql.goog"),
			},
			wantIP: "abcde.12345.my-region.sql.goog",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			var opts []mock.FakeCSQLInstanceOption
			opts = append(opts, mock.WithNoIPAddrs())
			opts = append(opts, tc.ips...)
			inst := mock.NewFakeCSQLInstance("my-project", "my-region", "my-instance", opts...)
			client, cleanup, err := mock.NewSQLAdminService(
				context.Background(),
				mock.InstanceGetSuccess(inst, 1),
				mock.CreateEphemeralSuccess(inst, 1),
			)
			if err != nil {
				t.Fatalf("%s", err)
			}
			defer func() {
				if cErr := cleanup(); cErr != nil {
					t.Fatalf("%v", cErr)
				}
			}()

			i := NewRefreshAheadCache(
				testInstanceConnName(), nullLogger{}, client,
				RSAKey, 30*time.Second, nil, "", false, nil,
			)

			ci, err := i.ConnectionInfo(context.Background())
			if err != nil {
				t.Fatalf("failed to retrieve connect info: %v", err)
			}

			got, err := ci.Addr(SQLData)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.wantIP {
				t.Fatalf(
					"ConnectInfo Addr returned unexpected IP address, want = %v, got = %v",
					tc.wantIP, got,
				)
			}

			gotAddrs, err := ci.Addrs(SQLData)
			if err != nil {
				t.Fatal(err)
			}
			if len(gotAddrs) == 0 || gotAddrs[0] != tc.wantIP {
				t.Fatalf(
					"ConnectInfo Addrs returned unexpected IP address, want = %v, got = %v",
					tc.wantIP, gotAddrs,
				)
			}
		})
	}
}

func TestClose(t *testing.T) {
	ctx := context.Background()

	client, cleanup, err := mock.NewSQLAdminService(ctx)
	if err != nil {
		t.Fatalf("%s", err)
	}
	defer cleanup()

	// Set up an instance and then close it immediately
	i := NewRefreshAheadCache(
		testInstanceConnName(), nullLogger{}, client,
		RSAKey, 30*time.Second, nil, "", false, nil,
	)
	i.Close()

	_, err = i.ConnectionInfo(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("failed to retrieve connect info: %v", err)
	}
}

func TestRefreshDuration(t *testing.T) {
	now := time.Now()
	tcs := []struct {
		desc   string
		expiry time.Time
		want   time.Duration
	}{
		{
			desc:   "when expiration is greater than 1 hour",
			expiry: now.Add(4 * time.Hour),
			want:   2 * time.Hour,
		},
		{
			desc:   "when expiration is equal to 1 hour",
			expiry: now.Add(time.Hour),
			want:   30 * time.Minute,
		},
		{
			desc:   "when expiration is less than 1 hour, but greater than 4 minutes",
			expiry: now.Add(5 * time.Minute),
			want:   time.Minute,
		},
		{
			desc:   "when expiration is less than 4 minutes",
			expiry: now.Add(3 * time.Minute),
			want:   0,
		},
		{
			desc:   "when expiration is now",
			expiry: now,
			want:   0,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			got := refreshDuration(now, tc.expiry)
			// round to the second to remove millisecond differences
			if got.Round(time.Second) != tc.want {
				t.Fatalf("time until refresh: want = %v, got = %v", tc.want, got)
			}
		})
	}
}

func TestConnectionInfoTLSConfigForCAS(t *testing.T) {
	cn := testInstanceConnName()
	i := mock.NewFakeCSQLInstance(cn.Project(), cn.Region(), cn.Name())
	// Generate a client certificate with the client's public key and signed by
	// the server's private key
	cert, err := i.ClientCert(&RSAKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	// Now parse the bytes back out as structured data
	b, _ := pem.Decode(cert)
	clientCert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	// Create a PEM with two certificates to pretend the sub CA and root CA.
	rootCABytes, err := mock.SelfSign(i.Cert, i.Key)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = pem.Decode(rootCABytes)
	rootCACert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	subCABytes, err := mock.SelfSign(i.Cert, i.Key)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = pem.Decode(subCABytes)
	subCACert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	caCerts := []*x509.Certificate{rootCACert, subCACert}
	wantRootCAs := x509.NewCertPool()
	wantRootCAs.AddCert(rootCACert)
	wantRootCAs.AddCert(subCACert)
	// Assemble a connection info with the raw and parsed client cert
	// and the self-signed server certificate
	wantServerName := "db.example.com"
	ci := ConnectionInfo{
		DNSName: wantServerName,
		ClientCertificate: tls.Certificate{
			Certificate: [][]byte{clientCert.Raw},
			PrivateKey:  RSAKey,
			Leaf:        clientCert,
		},
		ServerCACert: caCerts,
		DBVersion:    "doesn't matter here",
		Expiration:   clientCert.NotAfter,
		ServerCAMode: "GOOGLE_MANAGED_CAS_CA",
	}

	got := ci.TLSConfig()

	if got.ServerName != wantServerName {
		t.Fatalf(
			"ConnectInfo return unexpected server name in CLIENT_PROTOCOL_TLS Config, "+
				"want = %v, got = %v",
			wantServerName, got.ServerName,
		)
	}
	if got.MinVersion != tls.VersionTLS13 {
		t.Fatalf(
			"want CLIENT_PROTOCOL_TLS 1.3, got = %v", got.MinVersion,
		)
	}

	if len(got.CurvePreferences) != 0 {
		t.Fatalf(
			"want empty CurvePreferences so crypto/tls uses default post-quantum key exchange (X25519MLKEM768), got = %v",
			got.CurvePreferences,
		)
	}
	if got.Certificates[0].Leaf != ci.ClientCertificate.Leaf {
		t.Fatal("leaf certificates do not match")
	}
	if !got.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify is false, expected true")
	}
	if !got.RootCAs.Equal(wantRootCAs) {
		t.Fatalf("unexpected root CAs, got %v, want %v", got.RootCAs, wantRootCAs)
	}
}

func TestResolveAddrs(t *testing.T) {
	mk := func(addrs map[string][]string) ConnectionInfo {
		return ConnectionInfo{ConnectionName: testInstanceConnName(), addrs: addrs}
	}
	pub := map[string][]string{PublicIP: {"1.1.1.1"}}
	priv := map[string][]string{PrivateIP: {"10.0.0.1"}}
	psc := map[string][]string{PSC: {"abc.sql.goog"}}
	all := map[string][]string{PublicIP: {"1.1.1.1"}, PrivateIP: {"10.0.0.1"}, PSC: {"abc.sql.goog"}}

	tcs := []struct {
		desc         string
		ci           ConnectionInfo
		req          string
		wantAddr     string
		wantResolved string
		wantErr      bool
	}{
		{desc: "public requested", ci: mk(all), req: PublicIP, wantAddr: "1.1.1.1", wantResolved: PublicIP},
		{desc: "private requested", ci: mk(all), req: PrivateIP, wantAddr: "10.0.0.1", wantResolved: PrivateIP},
		{desc: "psc requested", ci: mk(all), req: PSC, wantAddr: "abc.sql.goog", wantResolved: PSC},
		{desc: "auto prefers public", ci: mk(all), req: AutoIP, wantAddr: "1.1.1.1", wantResolved: PublicIP},
		{desc: "auto falls back to private", ci: mk(priv), req: AutoIP, wantAddr: "10.0.0.1", wantResolved: PrivateIP},
		{desc: "auto with only psc fails", ci: mk(psc), req: AutoIP, wantErr: true},
		{desc: "sqldata prefers private", ci: mk(all), req: SQLData, wantAddr: "10.0.0.1", wantResolved: PrivateIP},
		{desc: "sqldata falls back to psc", ci: mk(psc), req: SQLData, wantAddr: "abc.sql.goog", wantResolved: PSC},
		{desc: "sqldata falls back to public", ci: mk(pub), req: SQLData, wantAddr: "1.1.1.1", wantResolved: PublicIP},
		{desc: "missing type fails", ci: mk(pub), req: PrivateIP, wantErr: true},
		{desc: "empty address list is treated as missing", ci: mk(map[string][]string{PublicIP: {}, PrivateIP: {"10.0.0.1"}}), req: AutoIP, wantAddr: "10.0.0.1", wantResolved: PrivateIP},
	}
	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			addrs, resolved, err := tc.ci.ResolveAddrs(tc.req)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got addrs=%v resolved=%q", addrs, resolved)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(addrs) == 0 || addrs[0] != tc.wantAddr {
				t.Errorf("addrs = %v, want first %q", addrs, tc.wantAddr)
			}
			if resolved != tc.wantResolved {
				t.Errorf("resolved = %q, want %q", resolved, tc.wantResolved)
			}
			// Addrs must agree with ResolveAddrs.
			a2, err := tc.ci.Addrs(tc.req)
			if err != nil || len(a2) == 0 || a2[0] != tc.wantAddr {
				t.Errorf("Addrs = %v, %v; want first %q", a2, err, tc.wantAddr)
			}
		})
	}
}

func TestRefreshAheadCache_ProbeConnection_Success(t *testing.T) {
	ctx := context.Background()
	inst := mock.NewFakeCSQLInstance("my-project", "my-region", "my-instance", mock.WithEngineVersion("POSTGRES_14"))
	client, cleanup, err := mock.NewSQLAdminService(
		ctx,
		mock.InstanceGetSuccess(inst, 2),
		mock.CreateEphemeralSuccess(inst, 2),
	)
	if err != nil {
		t.Fatalf("%s", err)
	}
	defer cleanup()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{inst.Cert.Raw},
			PrivateKey:  inst.Key,
		}},
	}
	tlsLn := tls.NewListener(ln, tlsConfig)
	defer tlsLn.Close()

	probed := make(chan struct{})
	go func() {
		conn, err := tlsLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		backend := pgproto3.NewBackend(conn, conn)
		if _, err := backend.ReceiveStartupMessage(); err == nil {
			backend.Send(&pgproto3.AuthenticationOk{})
			_ = backend.Flush()
			_, _ = backend.Receive()
		}
		close(probed)
	}()

	dialFunc := func(ctx context.Context, ci ConnectionInfo, _ string) (net.Conn, error) {
		var d net.Dialer
		conn, err := d.DialContext(ctx, "tcp", ln.Addr().String())
		if err != nil {
			return nil, err
		}
		tlsConn := tls.Client(conn, ci.TLSConfig())
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return tlsConn, nil
	}

	i := NewRefreshAheadCache(
		testInstanceConnName(), nullLogger{}, client,
		RSAKey, 30*time.Second, nil, "", true,
		dialFunc,
	)
	defer i.Close()

	_, err = i.ConnectionInfo(ctx)
	if err != nil {
		t.Fatalf("failed to retrieve connection info: %v", err)
	}

	i.RecordIAMPrincipal("iam-user@example.com", "mydb", "")
	i.ForceRefresh()
	_, err = i.ConnectionInfo(ctx)
	if err != nil {
		t.Fatalf("failed to refresh connection info: %v", err)
	}

	select {
	case <-probed:
		// Success: probe connection was accepted and TLS handshake completed
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for probe connection to be established")
	}
}

func TestRefreshAheadCache_ProbeConnection_DialErrorDoesNotFailRefresh(t *testing.T) {
	ctx := context.Background()
	inst := mock.NewFakeCSQLInstance("my-project", "my-region", "my-instance", mock.WithEngineVersion("POSTGRES_14"))
	client, cleanup, err := mock.NewSQLAdminService(
		ctx,
		mock.InstanceGetSuccess(inst, 2),
		mock.CreateEphemeralSuccess(inst, 2),
	)
	if err != nil {
		t.Fatalf("%s", err)
	}
	defer cleanup()

	dialed := make(chan struct{}, 1)
	dialFunc := func(_ context.Context, _ ConnectionInfo, _ string) (net.Conn, error) {
		select {
		case dialed <- struct{}{}:
		default:
		}
		return nil, errors.New("network unreachable")
	}

	i := NewRefreshAheadCache(
		testInstanceConnName(), nullLogger{}, client,
		RSAKey, 30*time.Second, nil, "", true,
		dialFunc,
	)
	defer i.Close()

	if _, err := i.ConnectionInfo(ctx); err != nil {
		t.Fatalf("initial ConnectionInfo failed: %v", err)
	}
	select {
	case <-dialed:
		t.Fatal("expected no probe dial before any IAM principal is recorded")
	default:
	}

	i.RecordIAMPrincipal("iam-user@example.com", "mydb", "")
	i.ForceRefresh()
	ci, err := i.ConnectionInfo(ctx)
	if err != nil {
		t.Fatalf("ConnectionInfo failed despite non-fatal probe error: %v", err)
	}
	if ci.DBVersion != "POSTGRES_14" {
		t.Fatalf("unexpected DBVersion: got %v, want POSTGRES_14", ci.DBVersion)
	}
	select {
	case <-dialed:
	case <-time.After(5 * time.Second):
		t.Fatal("expected probe dialFunc to be invoked for recorded Postgres IAM principal")
	}
}

func TestRefreshAheadCache_ProbeConnection_SkipsZeroPrincipalsAndNonPostgres(t *testing.T) {
	tcs := []struct {
		desc            string
		dbVersion       string
		recordPrincipal bool
	}{
		{
			desc:            "postgres with zero principals skips probe",
			dbVersion:       "POSTGRES_14",
			recordPrincipal: false,
		},
		{
			desc:            "mysql skips probe even with iam auth enabled",
			dbVersion:       "MYSQL_8_0",
			recordPrincipal: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			ctx := context.Background()
			inst := mock.NewFakeCSQLInstance("my-project", "my-region", "my-instance", mock.WithEngineVersion(tc.dbVersion))
			count := 1
			if tc.recordPrincipal {
				count = 2
			}
			client, cleanup, err := mock.NewSQLAdminService(
				ctx,
				mock.InstanceGetSuccess(inst, count),
				mock.CreateEphemeralSuccess(inst, count),
			)
			if err != nil {
				t.Fatalf("%s", err)
			}
			defer cleanup()

			dialed := make(chan struct{}, 1)
			dialFunc := func(_ context.Context, _ ConnectionInfo, _ string) (net.Conn, error) {
				select {
				case dialed <- struct{}{}:
				default:
				}
				return nil, errors.New("unexpected probe dial")
			}

			i := NewRefreshAheadCache(
				testInstanceConnName(), nullLogger{}, client,
				RSAKey, 30*time.Second, nil, "", true,
				dialFunc,
			)
			defer i.Close()

			if _, err := i.ConnectionInfo(ctx); err != nil {
				t.Fatalf("ConnectionInfo failed: %v", err)
			}
			if tc.recordPrincipal {
				i.RecordIAMPrincipal("iam-user@example.com", "mydb", "")
				i.ForceRefresh()
				if _, err := i.ConnectionInfo(ctx); err != nil {
					t.Fatalf("refreshed ConnectionInfo failed: %v", err)
				}
			}

			select {
			case <-dialed:
				t.Fatalf("expected 0 probe dials for %s", tc.desc)
			default:
			}
		})
	}

	t.Run("probeInstanceConnection skips non-postgres directly", func(t *testing.T) {
		dialFunc := func(_ context.Context, _ ConnectionInfo, _ string) (net.Conn, error) {
			t.Fatal("expected 0 probe dials for SQLSERVER")
			return nil, nil
		}
		err := probeInstanceConnection(
			context.Background(),
			ConnectionInfo{DBVersion: "SQLSERVER_2019_STANDARD"},
			5*time.Second,
			dialFunc,
			[]pgPrincipal{{user: "user@example.com", database: "db"}},
			nullLogger{},
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestRefreshAheadCache_ProbeConnection_PostgresStartupPacket(t *testing.T) {
	ctx := context.Background()
	inst := mock.NewFakeCSQLInstance("my-project", "my-region", "my-instance", mock.WithEngineVersion("POSTGRES_14"))
	client, cleanup, err := mock.NewSQLAdminService(
		ctx,
		mock.InstanceGetSuccess(inst, 2),
		mock.CreateEphemeralSuccess(inst, 2),
	)
	if err != nil {
		t.Fatalf("%s", err)
	}
	defer cleanup()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{inst.Cert.Raw},
			PrivateKey:  inst.Key,
		}},
	}
	tlsLn := tls.NewListener(ln, tlsConfig)
	defer tlsLn.Close()

	type probeRecord struct {
		user         string
		database     string
		sawTerminate bool
		err          error
	}
	startupProbeCh := make(chan probeRecord, 1)
	go func() {
		defer close(startupProbeCh)
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			rec, done := func(c net.Conn) (probeRecord, bool) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				backend := pgproto3.NewBackend(c, c)
				msg, err := backend.ReceiveStartupMessage()
				if err != nil {
					if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
						return probeRecord{}, false
					}
					return probeRecord{err: fmt.Errorf("ReceiveStartupMessage failed: %w", err)}, true
				}
				sm, ok := msg.(*pgproto3.StartupMessage)
				if !ok || sm.Parameters["user"] == "" {
					return probeRecord{err: fmt.Errorf("unexpected startup message: %T", msg)}, true
				}
				backend.Send(&pgproto3.AuthenticationOk{})
				backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
				_ = backend.Flush()
				nextMsg, _ := backend.Receive()
				_, sawTerm := nextMsg.(*pgproto3.Terminate)
				return probeRecord{
					user:         sm.Parameters["user"],
					database:     sm.Parameters["database"],
					sawTerminate: sawTerm,
				}, true
			}(conn)
			if done {
				startupProbeCh <- rec
				return
			}
		}
	}()

	dialFunc := func(ctx context.Context, ci ConnectionInfo, _ string) (net.Conn, error) {
		var d net.Dialer
		conn, err := d.DialContext(ctx, "tcp", ln.Addr().String())
		if err != nil {
			return nil, err
		}
		tlsConn := tls.Client(conn, ci.TLSConfig())
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return tlsConn, nil
	}

	i := NewRefreshAheadCache(
		testInstanceConnName(), nullLogger{}, client,
		RSAKey, 30*time.Second, nil, "", true,
		dialFunc,
	)
	defer i.Close()

	if _, err := i.ConnectionInfo(ctx); err != nil {
		t.Fatalf("initial ConnectionInfo failed: %v", err)
	}

	// Simulate an application connection capturing the PostgreSQL startup packet via sniffer.
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() {
		buf := make([]byte, 1024)
		for {
			if _, err := c2.Read(buf); err != nil {
				return
			}
		}
	}()
	pgConn := NewPostgresConn(c1, func(user, database string) {
		i.RecordIAMPrincipal(user, database, "")
	})
	// Write SSLRequest followed by StartupMessage using pgproto3
	sslReq, err := (&pgproto3.SSLRequest{}).Encode(nil)
	if err != nil {
		t.Fatalf("encode SSLRequest failed: %v", err)
	}
	if _, err := pgConn.Write(sslReq); err != nil {
		t.Fatalf("pgConn write SSLRequest failed: %v", err)
	}
	startupPkt, err := (&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersion30,
		Parameters: map[string]string{
			"user":     "iam-user@example.com",
			"database": "mydb",
		},
	}).Encode(nil)
	if err != nil {
		t.Fatalf("encode StartupMessage failed: %v", err)
	}
	// Break the initial startup request into multiple Write() calls to prove
	// connection state handles partial I/O.
	if _, err := pgConn.Write(startupPkt[0:1]); err != nil {
		t.Fatalf("pgConn write partial StartupMessage failed: %v", err)
	}
	if _, err := pgConn.Write(startupPkt[1:]); err != nil {
		t.Fatalf("pgConn write remaining StartupMessage failed: %v", err)
	}

	// Trigger a background refresh and verify probeConnection sends StartupMessage + Terminate.
	i.ForceRefresh()
	if _, err := i.ConnectionInfo(ctx); err != nil {
		t.Fatalf("refreshed ConnectionInfo failed: %v", err)
	}

	select {
	case rec, ok := <-startupProbeCh:
		if !ok {
			t.Fatal("startupProbeCh closed without receiving a startup probe packet")
		}
		if rec.err != nil {
			t.Fatalf("mock server error receiving startup probe packet: %v", rec.err)
		}
		if rec.user != "iam-user@example.com" || rec.database != "mydb" {
			t.Fatalf("unexpected startup probe principal: got (%q, %q), want (\"iam-user@example.com\", \"mydb\")", rec.user, rec.database)
		}
		if !rec.sawTerminate {
			t.Fatal("expected probe connection to send Terminate ('X') after reading server response")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for PostgreSQL startup probe packet")
	}
}

func TestPostgresConn_ChunkedWrites(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	go func() {
		buf := make([]byte, 1024)
		for {
			if _, err := c2.Read(buf); err != nil {
				return
			}
		}
	}()

	var (
		gotUser string
		gotDB   string
		calls   int
	)
	conn := NewPostgresConn(c1, func(u, db string) {
		gotUser = u
		gotDB = db
		calls++
	})

	// Encode SSLRequest and StartupMessage
	sslReq, err := (&pgproto3.SSLRequest{}).Encode(nil)
	if err != nil {
		t.Fatal(err)
	}
	startupPkt, err := (&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersion30,
		Parameters: map[string]string{
			"user":     "stream-user@example.com",
			"database": "streamdb",
		},
	}).Encode(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Write SSLRequest in 2 chunks
	mid := len(sslReq) / 2
	if _, err := conn.Write(sslReq[:mid]); err != nil {
		t.Fatalf("Write sslReq chunk 1 failed: %v", err)
	}
	if _, err := conn.Write(sslReq[mid:]); err != nil {
		t.Fatalf("Write sslReq chunk 2 failed: %v", err)
	}
	if calls != 0 {
		t.Fatalf("expected 0 onStartup calls after SSLRequest, got %d", calls)
	}

	// Write StartupMessage 1 byte at a time to test fine-grained streaming
	for i := 0; i < len(startupPkt)-1; i++ {
		if _, err := conn.Write(startupPkt[i : i+1]); err != nil {
			t.Fatalf("Write byte %d failed: %v", i, err)
		}
		if calls != 0 {
			t.Fatalf("expected 0 onStartup calls before final byte, got %d at index %d", calls, i)
		}
	}

	// Write final byte
	if _, err := conn.Write(startupPkt[len(startupPkt)-1:]); err != nil {
		t.Fatalf("Write final byte failed: %v", err)
	}

	if calls != 1 {
		t.Fatalf("expected exactly 1 onStartup call, got %d", calls)
	}
	if gotUser != "stream-user@example.com" || gotDB != "streamdb" {
		t.Fatalf("unexpected user/db: got (%q, %q), want (\"stream-user@example.com\", \"streamdb\")", gotUser, gotDB)
	}

	// Subsequent write passes through directly
	if _, err := conn.Write([]byte("QSELECT 1;\x00")); err != nil {
		t.Fatalf("Subsequent write failed: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected no additional onStartup calls on subsequent writes, got %d", calls)
	}
}

func TestPostgresConn_GSSAndSSLRequest(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	go func() {
		buf := make([]byte, 1024)
		for {
			if _, err := c2.Read(buf); err != nil {
				return
			}
		}
	}()

	var (
		gotUser string
		gotDB   string
		calls   int
	)
	conn := NewPostgresConn(c1, func(u, db string) {
		gotUser = u
		gotDB = db
		calls++
	})

	gssReq, err := (&pgproto3.GSSEncRequest{}).Encode(nil)
	if err != nil {
		t.Fatal(err)
	}
	sslReq, err := (&pgproto3.SSLRequest{}).Encode(nil)
	if err != nil {
		t.Fatal(err)
	}
	startupPkt, err := (&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersion30,
		Parameters: map[string]string{
			"user":     "gss-user@example.com",
			"database": "gssdb",
		},
	}).Encode(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Write GSSEncRequest, then SSLRequest, then StartupMessage
	if _, err := conn.Write(gssReq); err != nil {
		t.Fatalf("Write gssReq failed: %v", err)
	}
	if calls != 0 {
		t.Fatalf("expected 0 calls after GSSEncRequest, got %d", calls)
	}

	if _, err := conn.Write(sslReq); err != nil {
		t.Fatalf("Write sslReq failed: %v", err)
	}
	if calls != 0 {
		t.Fatalf("expected 0 calls after SSLRequest, got %d", calls)
	}

	if _, err := conn.Write(startupPkt); err != nil {
		t.Fatalf("Write startupPkt failed: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call after StartupMessage, got %d", calls)
	}
	if gotUser != "gss-user@example.com" || gotDB != "gssdb" {
		t.Fatalf("unexpected user/db: got (%q, %q), want (\"gss-user@example.com\", \"gssdb\")", gotUser, gotDB)
	}
}

func TestPostgresConn_PipelinedWrite(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	var received bytes.Buffer
	doneReading := make(chan struct{})
	go func() {
		defer close(doneReading)
		buf := make([]byte, 1024)
		for {
			n, err := c2.Read(buf)
			if n > 0 {
				received.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	var (
		gotUser string
		gotDB   string
		calls   int
	)
	conn := NewPostgresConn(c1, func(u, db string) {
		gotUser = u
		gotDB = db
		calls++
	})

	startupPkt, err := (&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersion30,
		Parameters: map[string]string{
			"user":     "pipelined-user@example.com",
			"database": "pipelinedb",
		},
	}).Encode(nil)
	if err != nil {
		t.Fatal(err)
	}

	queryPkt := []byte("QSELECT 1;\x00")
	combined := append(startupPkt, queryPkt...)

	// Write both in a single pipelined write
	n, err := conn.Write(combined)
	if err != nil {
		t.Fatalf("Write combined failed: %v", err)
	}
	if n != len(combined) {
		t.Fatalf("wrote %d bytes, want %d", n, len(combined))
	}

	if calls != 1 {
		t.Fatalf("expected 1 call after pipelined write, got %d", calls)
	}
	if gotUser != "pipelined-user@example.com" || gotDB != "pipelinedb" {
		t.Fatalf("unexpected user/db: got (%q, %q)", gotUser, gotDB)
	}

	c1.Close()
	<-doneReading
	if !bytes.Equal(received.Bytes(), combined) {
		t.Fatalf("wire received bytes mismatch: got %d bytes, want %d", received.Len(), len(combined))
	}
}

func TestRefreshAheadCache_ProbeConnection_PreservesIPTypeAndDeduplicates(t *testing.T) {
	inst := mock.NewFakeCSQLInstance("my-project", "my-region", "my-instance", mock.WithEngineVersion("POSTGRES_15"))
	client, cleanup, err := mock.NewSQLAdminService(
		context.Background(),
		mock.InstanceGetSuccess(inst, 2),
		mock.CreateEphemeralSuccess(inst, 2),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	probedIPTypes := make(chan string, 4)
	dialFunc := func(_ context.Context, _ ConnectionInfo, ipType string) (net.Conn, error) {
		probedIPTypes <- ipType
		return nil, errors.New("stop after recording ipType")
	}

	i := NewRefreshAheadCache(
		testInstanceConnName(), nullLogger{}, client,
		RSAKey, 5*time.Second, nil, "", true,
		dialFunc,
	)
	defer i.Close()

	if _, err := i.ConnectionInfo(context.Background()); err != nil {
		t.Fatalf("initial ConnectionInfo failed: %v", err)
	}

	// Duplicate (user, db, ipType) should deduplicate, while differing ipType must stay distinct.
	i.RecordIAMPrincipal("u1@example.com", "db1", PrivateIP)
	i.RecordIAMPrincipal("u1@example.com", "db1", PrivateIP)
	i.RecordIAMPrincipal("u1@example.com", "db1", PublicIP)
	i.RecordIAMPrincipal("u2@example.com", "db2", PSC)

	i.ForceRefresh()

	want := []string{PrivateIP, PublicIP, PSC}
	var got []string
	for len(got) < len(want) {
		select {
		case ipType := <-probedIPTypes:
			got = append(got, ipType)
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for probe dials; got %v, want %v", got, want)
		}
	}
	for idx := range want {
		if got[idx] != want[idx] {
			t.Fatalf("dialed ipTypes[%d] = %q, want %q (all=%v)", idx, got[idx], want[idx], got)
		}
	}
	select {
	case extra := <-probedIPTypes:
		t.Fatalf("unexpected duplicate probe dial for ipType %q", extra)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestProbeInstanceConnection_BoundedEOFDrainAfterTerminate(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var mu sync.Mutex
	var probedUsers []string
	var heldConns []net.Conn
	defer func() {
		mu.Lock()
		for _, c := range heldConns {
			_ = c.Close()
		}
		mu.Unlock()
	}()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				backend := pgproto3.NewBackend(c, c)
				msg, err := backend.ReceiveStartupMessage()
				if err != nil {
					_ = c.Close()
					return
				}
				sm, ok := msg.(*pgproto3.StartupMessage)
				if !ok {
					_ = c.Close()
					return
				}
				user := sm.Parameters["user"]
				backend.Send(&pgproto3.AuthenticationOk{})
				backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
				if err := backend.Flush(); err != nil {
					_ = c.Close()
					return
				}
				if _, err := backend.Receive(); err != nil {
					_ = c.Close()
					return
				}
				mu.Lock()
				probedUsers = append(probedUsers, user)
				if user == "u1@example.com" {
					// Intentionally keep connection open without TCP FIN.
					heldConns = append(heldConns, c)
					mu.Unlock()
					return
				}
				mu.Unlock()
				_ = c.Close()
			}(c)
		}
	}()

	dialFunc := func(ctx context.Context, _ ConnectionInfo, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
	}

	start := time.Now()
	err = probeInstanceConnection(
		context.Background(),
		ConnectionInfo{
			ConnectionName: testInstanceConnName(),
			DBVersion:      "POSTGRES_15",
		},
		5*time.Second,
		dialFunc,
		[]pgPrincipal{
			{user: "u1@example.com", database: "db1", ipType: PrivateIP},
			{user: "u2@example.com", database: "db2", ipType: PrivateIP},
		},
		nullLogger{},
	)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("probeInstanceConnection failed: %v", err)
	}
	if elapsed >= 2*time.Second {
		t.Fatalf("probeInstanceConnection took %v, expected bounded drain around ~%v without burning 5s budget", elapsed, probeEOFDrainTimeout)
	}

	mu.Lock()
	got := append([]string(nil), probedUsers...)
	mu.Unlock()
	if len(got) != 2 || got[0] != "u1@example.com" || got[1] != "u2@example.com" {
		t.Fatalf("probed users = %v, want [u1@example.com u2@example.com]", got)
	}
}

// TestRefreshAheadCacheClosedWhileWaitingReturnsDialError guards the error a
// caller sees when the cache is closed under it (Dialer.Close, a removed
// entry, or a DNS failover) while its own context is still live: a dial error
// it can classify, not a bare context error it would attribute to itself.
func TestRefreshAheadCacheClosedWhileWaitingReturnsDialError(t *testing.T) {
	cn := testInstanceConnName()
	release := make(chan struct{})
	stalled := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-release
	}))
	defer stalled.Close()
	defer close(release)
	client, err := sqladmin.NewService(context.Background(),
		option.WithHTTPClient(stalled.Client()), option.WithEndpoint(stalled.URL))
	if err != nil {
		t.Fatal(err)
	}

	i := NewRefreshAheadCache(cn, nullLogger{}, client, RSAKey, 30*time.Second, nil, "", false, nil)
	done := make(chan error, 1)
	go func() {
		_, err := i.ConnectionInfo(context.Background())
		done <- err
	}()
	// Give the caller time to start waiting on the first refresh.
	time.Sleep(100 * time.Millisecond)
	if err := i.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case err = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ConnectionInfo() did not return after Close()")
	}
	var de *errtype.DialError
	if !errors.As(err, &de) {
		t.Errorf("ConnectionInfo() err = %T %v, want a *errtype.DialError", err, err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("ConnectionInfo() err = %v, want it to wrap %v", err, context.Canceled)
	}
}
