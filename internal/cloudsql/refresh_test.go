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

package cloudsql

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/cloudsqlconn/internal/mock"
	"google.golang.org/api/option"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

func errorContains(err error, want string) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), want)
}

func TestRefresh(t *testing.T) {
	wantPublicIP := "127.0.0.1"
	wantPrivateIP := "10.0.0.1"
	wantExpiry := time.Now().Add(time.Hour).UTC().Round(time.Second)
	wantConnName := "my-project:my-region:my-instance"
	cn, err := parseConnName(wantConnName)
	inst := mock.NewFakeCSQLInstance(
		"my-project", "my-region", "my-instance",
		mock.WithPublicIP(wantPublicIP),
		mock.WithPrivateIP(wantPrivateIP),
		mock.WithCertExpiry(wantExpiry),
	)
	client, cleanup, err := mock.NewSQLAdminService(
		context.Background(),
		mock.InstanceGetSuccess(inst, 1),
		mock.CreateEphemeralSuccess(inst, 1),
	)
	if err != nil {
		t.Fatalf("failed to create test SQL admin service: %s", err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			t.Fatalf("%v", err)
		}
	}()

	r := newRefresher(time.Hour, 30*time.Second, 2, client)
	md, tlsCfg, gotExpiry, err := r.performRefresh(context.Background(), cn, RSAKey)
	if err != nil {
		t.Fatalf("PerformRefresh unexpectedly failed with error: %v", err)
	}

	gotIP, ok := md.ipAddrs[PublicIP]
	if !ok {
		t.Fatalf("metadata IP addresses did not include public address")
	}
	if wantPublicIP != gotIP {
		t.Fatalf("metadata IP mismatch, want = %v, got = %v", wantPublicIP, gotIP)
	}
	gotIP, ok = md.ipAddrs[PrivateIP]
	if !ok {
		t.Fatalf("metadata IP addresses did not include private address")
	}
	if wantPrivateIP != gotIP {
		t.Fatalf("metadata IP mismatch, want = %v, got = %v", wantPrivateIP, gotIP)
	}
	if wantExpiry != gotExpiry {
		t.Fatalf("expiry mismatch, want = %v, got = %v", wantExpiry, gotExpiry)
	}
	if wantConnName != tlsCfg.ServerName {
		t.Fatalf("server name mismatch, want = %v, got = %v", wantConnName, tlsCfg.ServerName)
	}
}

func TestRefreshFailsFast(t *testing.T) {
	cn, _ := parseConnName("my-project:my-region:my-instance")
	inst := mock.NewFakeCSQLInstance("my-project", "my-region", "my-instance")
	client, cleanup, err := mock.NewSQLAdminService(
		context.Background(),
		mock.InstanceGetSuccess(inst, 1),
		mock.CreateEphemeralSuccess(inst, 1),
	)
	if err != nil {
		t.Fatalf("failed to create test SQL admin service: %s", err)
	}
	defer cleanup()

	r := newRefresher(time.Hour, 30*time.Second, 1, client)
	_, _, _, err = r.performRefresh(context.Background(), cn, RSAKey)
	if err != nil {
		t.Fatalf("expected no error, got = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// context is canceled
	_, _, _, err = r.performRefresh(ctx, cn, RSAKey)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled error, got = %v", err)
	}

	// force the rate limiter to throttle with a timed out context
	ctx, _ = context.WithTimeout(context.Background(), time.Millisecond)
	_, _, _, err = r.performRefresh(ctx, cn, RSAKey)

	if !errorContains(err, "throttled") {
		t.Fatalf("expected throttled error, got = %v", err)
	}
}

func TestRefreshWithFailedMetadataCall(t *testing.T) {
	cn, _ := parseConnName("my-project:my-region:my-instance")

	testCases := []struct {
		req     *mock.Request
		wantErr string
		desc    string
	}{
		{
			req: mock.CreateEphemeralSuccess(
				mock.NewFakeCSQLInstance(cn.project, cn.region, cn.name), 1),
			wantErr: "failed to get instance",
			desc:    "When the Metadata call fails",
		},
		{
			req: mock.InstanceGetSuccess(
				mock.NewFakeCSQLInstance(cn.project, cn.region, cn.name,
					mock.WithRegion("some-other-region")), 1),
			wantErr: "region was mismatched",
			desc:    "When the region does not match",
		},
		{
			req: mock.InstanceGetSuccess(
				mock.NewFakeCSQLInstance(
					cn.project, cn.region, cn.name,
					mock.WithRegion("my-region"),
					mock.WithFirstGenBackend(),
				), 1),
			wantErr: "only Second Generation",
			desc:    "When the instance isn't Second generation",
		},
		{
			req: mock.InstanceGetSuccess(
				mock.NewFakeCSQLInstance(
					cn.project, cn.region, cn.name,
					mock.WithRegion("my-region"),
					mock.WithMissingIPAddrs(),
				), 1),
			wantErr: "no supported IP addresses",
			desc:    "When the instance has no supported IP addresses",
		},
		{
			req: mock.InstanceGetSuccess(
				mock.NewFakeCSQLInstance(
					cn.project, cn.region, cn.name,
					mock.WithRegion("my-region"),
					mock.WithCertSigner(func(_ *x509.Certificate, _ *rsa.PrivateKey) ([]byte, error) {
						return nil, nil
					}),
				), 1),
			wantErr: "failed to decode",
			desc:    "When the server cert does not decode",
		},
		{
			req: mock.InstanceGetSuccess(
				mock.NewFakeCSQLInstance(
					cn.project, cn.region, cn.name,
					mock.WithRegion("my-region"),
					mock.WithCertSigner(func(_ *x509.Certificate, _ *rsa.PrivateKey) ([]byte, error) {
						certPEM := &bytes.Buffer{}
						pem.Encode(certPEM, &pem.Block{
							Type:  "CERTIFICATE",
							Bytes: []byte("hello"), // woops no cert
						})
						return certPEM.Bytes(), nil
					}),
				), 1),
			wantErr: "failed to parse",
			desc:    "When the cert is not a valid X.509 cert",
		},
	}
	for i, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			client, cleanup, err := mock.NewSQLAdminService(
				context.Background(),
				tc.req,
			)
			if err != nil {
				t.Fatalf("failed to create test SQL admin service: %s", err)
			}
			defer cleanup()

			r := newRefresher(time.Hour, 30*time.Second, 1, client)
			_, _, _, err = r.performRefresh(context.Background(), cn, RSAKey)

			if !errorContains(err, tc.wantErr) {
				t.Errorf("[%v] PerformRefresh failed with unexpected error, want = %v, got = %v", i, tc.wantErr, err)
			}
		})
	}
}

func TestRefreshWithFailedEphemeralCertCall(t *testing.T) {
	cn, _ := parseConnName("my-project:my-region:my-instance")
	inst := mock.NewFakeCSQLInstance(cn.project, cn.region, cn.name)

	testCases := []struct {
		req     *mock.Request
		wantErr string
		desc    string
	}{
		{
			req:     mock.InstanceGetSuccess(inst, 1), // not an ephemeral cert call
			wantErr: "fetch ephemeral cert failed",
			desc:    "When the CreateEphemeralCert call fails",
		},
	}
	for i, tc := range testCases {
		mc, url, cleanup := mock.HTTPClient(mock.InstanceGetSuccess(inst, 1), tc.req)
		client, err := sqladmin.NewService(
			context.Background(),
			option.WithHTTPClient(mc),
			option.WithEndpoint(url),
		)
		if err != nil {
			t.Fatalf("failed to create test SQL admin service: %s", err)
		}
		defer cleanup()

		r := newRefresher(time.Hour, 30*time.Second, 1, client)
		_, _, _, err = r.performRefresh(context.Background(), cn, RSAKey)

		if !errorContains(err, tc.wantErr) {
			t.Errorf("[%v] PerformRefresh failed with unexpected error, want = %v, got = %v", i, tc.wantErr, err)
		}
	}
}

func TestRefreshBuildsTLSConfig(t *testing.T) {
	wantServerName := "my-project:my-region:my-instance"
	cn, _ := parseConnName(wantServerName)
	inst := mock.NewFakeCSQLInstance(cn.project, cn.region, cn.name)
	certBytes, err := mock.SelfSign(inst.Cert, inst.Key)
	if err != nil {
		t.Fatalf("failed to sign certificate: %v", err)
	}
	mc, url, cleanup := mock.HTTPClient(
		mock.InstanceGetSuccess(inst, 1), // no server cert
		mock.CreateEphemeralSuccess(inst, 1),
	)
	defer cleanup()
	client, err := sqladmin.NewService(
		context.Background(),
		option.WithHTTPClient(mc),
		option.WithEndpoint(url),
	)
	if err != nil {
		t.Fatalf("failed to create test SQL admin service: %s", err)
	}

	r := newRefresher(time.Hour, 30*time.Second, 1, client)
	_, tlsCfg, _, err := r.performRefresh(context.Background(), cn, RSAKey)
	if err != nil {
		t.Fatalf("expected no error, got = %v", err)
	}

	if wantServerName != tlsCfg.ServerName {
		t.Fatalf(
			"TLS config has incorrect server name, want = %v, got = %v",
			wantServerName, tlsCfg.ServerName,
		)
	}

	wantCertLen := 1
	if wantCertLen != len(tlsCfg.Certificates) {
		t.Fatalf(
			"TLS config has unexpected number of certificates, want = %v, got = %v",
			wantCertLen, len(tlsCfg.Certificates),
		)
	}

	wantInsecure := true
	if wantInsecure != tlsCfg.InsecureSkipVerify {
		t.Fatalf(
			"TLS config should skip verification, want = %v, got = %v",
			wantInsecure, tlsCfg.InsecureSkipVerify,
		)
	}

	if tlsCfg.RootCAs == nil {
		t.Fatal("TLS config should include RootCA, got nil")
	}

	verifyPeerCert := tlsCfg.VerifyPeerCertificate
	b, _ := pem.Decode(certBytes)
	err = verifyPeerCert([][]byte{b.Bytes}, nil)
	if err != nil {
		t.Fatalf("expected to verify peer cert, got error: %v", err)
	}

	err = verifyPeerCert(nil, nil)
	if !errorContains(err, "no certificate") {
		t.Fatalf("expected verify peer cert to fail, got = %v", err)
	}

	err = verifyPeerCert([][]byte{[]byte("not a cert")}, nil)
	if !errorContains(err, "x509.ParseCertificate(rawCerts[0])") {
		t.Fatalf("expected verify peer cert to fail on invalid cert, got = %v", err)
	}

	badCert := mock.GenerateCertWithCommonName(inst, "wrong:wrong")
	err = verifyPeerCert([][]byte{badCert}, nil)
	if !errorContains(err, "certificate had CN") {
		t.Fatalf("expected common name mistmatch to error, got = %v", err)
	}

	other := mock.NewFakeCSQLInstance(cn.project, cn.region, cn.name)
	certBytes, err = mock.SelfSign(other.Cert, other.Key)
	if err != nil {
		t.Fatalf("failed to sign certificate: %v", err)
	}
	b, _ = pem.Decode(certBytes)
	err = verifyPeerCert([][]byte{b.Bytes}, nil)
	if !errorContains(err, "signed by unknown authority") {
		t.Fatalf("expected certificate verification to fail, got = %v", err)
	}
}
