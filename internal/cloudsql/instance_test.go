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
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"cloud.google.com/go/cloudsqlconn/errtype"
	"cloud.google.com/go/cloudsqlconn/instance"
	"cloud.google.com/go/cloudsqlconn/internal/mock"
)

type nullLogger struct{}

func (nullLogger) Debugf(string, ...interface{}) {}

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

func TestInstanceEngineVersion(t *testing.T) {
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
			RSAKey, 30*time.Second, nil, "", false,
		)
		if err != nil {
			t.Fatalf("failed to init instance: %v", err)
		}

		gotEV, err := i.InstanceEngineVersion(ctx)
		if err != nil {
			t.Fatalf("failed to retrieve engine version: %v", err)
		}
		if wantEV != gotEV {
			t.Errorf("InstanceEngineVersion(%s) failed: want %v, got %v", wantEV, gotEV, err)
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
		RSAKey, 30*time.Second, nil, "", false,
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

	// Now self sign the server's cert
	// TODO: this also should return structured data and handle the PEM
	// encoding elsewhere
	certBytes, err := mock.SelfSign(i.Cert, i.Key)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = pem.Decode(certBytes)
	serverCert, err := x509.ParseCertificate(b.Bytes)
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
		ServerCaCert: serverCert,
		DBVersion:    "doesn't matter here",
		Expiration:   clientCert.NotAfter,
	}

	got := ci.TLSConfig()
	wantServerName := cn.String()
	if got.ServerName != wantServerName {
		t.Fatalf(
			"ConnectInfo return unexpected server name in TLS Config, "+
				"want = %v, got = %v",
			wantServerName, got.ServerName,
		)
	}

	if got.MinVersion != tls.VersionTLS13 {
		t.Fatalf(
			"want TLS 1.3, got = %v", got.MinVersion,
		)
	}

	if got.Certificates[0].Leaf != ci.ClientCertificate.Leaf {
		t.Fatal("leaf certificates do not match")
	}

	verifyPeerCert := got.VerifyPeerCertificate
	err = verifyPeerCert([][]byte{serverCert.Raw}, nil)
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
			RSAKey, 30*time.Second, nil, "", false,
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
		RSAKey, 30*time.Second, nil, "", false,
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

func TestContextCancelled(t *testing.T) {
	ctx := context.Background()

	client, cleanup, err := mock.NewSQLAdminService(ctx)
	if err != nil {
		t.Fatalf("%s", err)
	}
	defer cleanup()

	// Set up an instance and then close it immediately
	i := NewRefreshAheadCache(
		testInstanceConnName(), nullLogger{}, client,
		RSAKey, 30*time.Second, nil, "", false,
	)
	if err != nil {
		t.Fatalf("failed to initialize Instance: %v", err)
	}
	i.Close()

	// grab the current value of next before scheduling another refresh
	i.mu.Lock()
	next := i.next
	i.mu.Unlock()

	op := i.scheduleRefresh(time.Nanosecond)
	<-op.ready

	i.mu.Lock()
	otherNext := i.next
	i.mu.Unlock()

	// if scheduleRefresh returns without scheduling another one,
	// i.next should be untouched and remain the same pointer value
	if otherNext != next {
		t.Fatalf("refresh did not return after a closed context. next pointer changed: want = %p, got = %p", next, i.next)
	}
}
