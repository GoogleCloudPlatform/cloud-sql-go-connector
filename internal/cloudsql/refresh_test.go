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
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/cloudsqlconn/errtype"
	"cloud.google.com/go/cloudsqlconn/internal/mock"
	"golang.org/x/oauth2"
)

const testDialerID = "some-dialer-id"

func TestRefresh(t *testing.T) {
	wantPublicIP := "127.0.0.1"
	wantPrivateIP := "10.0.0.1"
	wantPSC := "abcde.12345.us-central1.sql.goog"
	wantExpiry := time.Now().Add(time.Hour).UTC().Round(time.Second)
	wantConnName := "my-project:my-region:my-instance"
	cn, err := ParseConnName(wantConnName)
	if err != nil {
		t.Fatalf("ParseConnName(%s)failed : %v", cn, err)
	}
	inst := mock.NewFakeCSQLInstance(
		"my-project", "my-region", "my-instance",
		mock.WithPublicIP(wantPublicIP),
		mock.WithPrivateIP(wantPrivateIP),
		mock.WithPSC(wantPSC),
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

	r := newRefresher(client, nil, testDialerID)
	rr, err := r.performRefresh(context.Background(), cn, RSAKey, false)
	if err != nil {
		t.Fatalf("PerformRefresh unexpectedly failed with error: %v", err)
	}

	gotIP, ok := rr.ipAddrs[PublicIP]
	if !ok {
		t.Fatal("metadata IP addresses did not include public address")
	}
	if wantPublicIP != gotIP {
		t.Fatalf("metadata IP mismatch, want = %v, got = %v", wantPublicIP, gotIP)
	}
	gotIP, ok = rr.ipAddrs[PrivateIP]
	if !ok {
		t.Fatal("metadata IP addresses did not include private address")
	}
	if wantPrivateIP != gotIP {
		t.Fatalf("metadata IP mismatch, want = %v, got = %v", wantPrivateIP, gotIP)
	}
	gotPSC, ok := rr.ipAddrs[PSC]
	if !ok {
		t.Fatal("metadata IP addresses did not include PSC endpoint")
	}
	if wantPSC != gotPSC {
		t.Fatalf("metadata IP mismatch, want = %v. got = %v", wantPSC, gotPSC)
	}
	if wantExpiry != rr.expiry {
		t.Fatalf("expiry mismatch, want = %v, got = %v", wantExpiry, rr.expiry)
	}
	if wantConnName != rr.conf.ServerName {
		t.Fatalf("server name mismatch, want = %v, got = %v", wantConnName, rr.conf.ServerName)
	}
}

func TestRefreshFailsFast(t *testing.T) {
	cn, _ := ParseConnName("my-project:my-region:my-instance")
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

	r := newRefresher(client, nil, testDialerID)
	_, err = r.performRefresh(context.Background(), cn, RSAKey, false)
	if err != nil {
		t.Fatalf("expected no error, got = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// context is canceled
	_, err = r.performRefresh(ctx, cn, RSAKey, false)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled error, got = %v", err)
	}
}

type tokenResp struct {
	tok *oauth2.Token
	err error
}

type fakeTokenSource struct {
	responses []tokenResp
	mu        sync.Mutex
	ct        int
}

func (f *fakeTokenSource) Token() (*oauth2.Token, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	resp := f.responses[f.ct]
	f.ct++
	return resp.tok, resp.err
}

func (f *fakeTokenSource) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ct
}

func TestRefreshAdjustsCertExpiry(t *testing.T) {
	certExpiry := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	t1 := time.Now().Add(59 * time.Minute).UTC().Truncate(time.Second)
	t2 := time.Now().Add(61 * time.Minute).UTC().Truncate(time.Second)
	tcs := []struct {
		desc       string
		resps      []tokenResp
		wantExpiry time.Time
	}{
		{
			desc: "when the token's expiration comes BEFORE the cert",
			resps: []tokenResp{
				{tok: &oauth2.Token{}},
				{tok: &oauth2.Token{Expiry: t1}},
			},
			wantExpiry: t1,
		},
		{
			desc: "when the token's expiration comes AFTER the cert",
			resps: []tokenResp{
				{tok: &oauth2.Token{}},
				{tok: &oauth2.Token{Expiry: t2}},
			},
			wantExpiry: certExpiry,
		},
	}
	cn, _ := ParseConnName("my-project:my-region:my-instance")
	inst := mock.NewFakeCSQLInstance("my-project", "my-region", "my-instance",
		mock.WithCertExpiry(certExpiry))
	client, cleanup, err := mock.NewSQLAdminService(
		context.Background(),
		mock.InstanceGetSuccess(inst, 2),
		mock.CreateEphemeralSuccess(inst, 2),
	)
	if err != nil {
		t.Fatalf("failed to create test SQL admin service: %s", err)
	}
	defer cleanup()

	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			ts := &fakeTokenSource{responses: tc.resps}
			r := newRefresher(client, ts, testDialerID)
			rr, err := r.performRefresh(context.Background(), cn, RSAKey, true)
			if err != nil {
				t.Fatalf("want no error, got = %v", err)
			}
			if tc.wantExpiry != rr.expiry {
				t.Fatalf("want = %v, got = %v", tc.wantExpiry, rr.expiry)
			}
		})
	}
}

func TestRefreshWithIAMAuthErrors(t *testing.T) {
	tcs := []struct {
		desc      string
		resps     []tokenResp
		wantCount int
	}{
		{
			desc:      "when fetching a token fails",
			resps:     []tokenResp{{tok: nil, err: errors.New("fetch failed")}},
			wantCount: 1,
		},
		{
			desc: "when refreshing a token fails",
			resps: []tokenResp{
				{tok: &oauth2.Token{}, err: nil},
				{tok: nil, err: errors.New("refresh failed")},
			},
			wantCount: 2,
		},
	}
	cn, _ := ParseConnName("my-project:my-region:my-instance")
	inst := mock.NewFakeCSQLInstance("my-project", "my-region", "my-instance")
	client, cleanup, err := mock.NewSQLAdminService(
		context.Background(),
		mock.InstanceGetSuccess(inst, 2),
	)
	if err != nil {
		t.Fatalf("failed to create test SQL admin service: %s", err)
	}
	defer cleanup()

	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			ts := &fakeTokenSource{responses: tc.resps}
			r := newRefresher(client, ts, testDialerID)
			_, err := r.performRefresh(context.Background(), cn, RSAKey, true)
			if err == nil {
				t.Fatalf("expected get failed error, got = %v", err)
			}
			if count := ts.count(); count != tc.wantCount {
				t.Fatalf("expected fake token source to be called %v time, got = %v", tc.wantCount, count)
			}
		})
	}
}

func TestRefreshMetadataConfigError(t *testing.T) {
	cn, _ := ParseConnName("my-project:my-region:my-instance")

	testCases := []struct {
		req     *mock.Request
		wantErr *errtype.ConfigError
		desc    string
	}{
		{
			req: mock.InstanceGetSuccess(
				mock.NewFakeCSQLInstance(
					cn.project, cn.region, cn.name,
					mock.WithRegion("my-region"),
					mock.WithFirstGenBackend(),
				), 1),
			wantErr: &errtype.ConfigError{},
			desc:    "When the instance isn't Second generation",
		},
		{
			req: mock.InstanceGetSuccess(
				mock.NewFakeCSQLInstance(cn.project, cn.region, cn.name,
					mock.WithRegion("some-other-region")), 1),
			wantErr: &errtype.ConfigError{},
			desc:    "When the region does not match",
		},
		{
			req: mock.InstanceGetSuccess(
				mock.NewFakeCSQLInstance(
					cn.project, cn.region, cn.name,
					mock.WithRegion("my-region"),
					mock.WithNoIPAddrs(),
				), 1),
			wantErr: &errtype.ConfigError{},
			desc:    "When the instance has no supported IP addresses",
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

			r := newRefresher(client, nil, testDialerID)
			_, err = r.performRefresh(context.Background(), cn, RSAKey, false)
			if !errors.As(err, &tc.wantErr) {
				t.Errorf("[%v] PerformRefresh failed with unexpected error, want = %T, got = %v", i, tc.wantErr, err)
			}
		})
	}
}

func TestRefreshMetadataRefreshError(t *testing.T) {
	cn, _ := ParseConnName("my-project:my-region:my-instance")

	testCases := []struct {
		req     *mock.Request
		wantErr *errtype.RefreshError
		desc    string
	}{
		{
			req: mock.CreateEphemeralSuccess(
				mock.NewFakeCSQLInstance(cn.project, cn.region, cn.name), 1),
			wantErr: &errtype.RefreshError{},
			desc:    "When the Metadata call fails",
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
			wantErr: &errtype.RefreshError{},
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
			wantErr: &errtype.RefreshError{},
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

			r := newRefresher(client, nil, testDialerID)
			_, err = r.performRefresh(context.Background(), cn, RSAKey, false)
			if !errors.As(err, &tc.wantErr) {
				t.Errorf("[%v] PerformRefresh failed with unexpected error, want = %T, got = %v", i, tc.wantErr, err)
			}
		})
	}
}

func TestRefreshWithFailedEphemeralCertCall(t *testing.T) {
	cn, _ := ParseConnName("my-project:my-region:my-instance")
	inst := mock.NewFakeCSQLInstance(cn.project, cn.region, cn.name)

	testCases := []struct {
		reqs    []*mock.Request
		wantErr *errtype.RefreshError
		desc    string
	}{
		{
			reqs:    []*mock.Request{mock.InstanceGetSuccess(inst, 1)}, // no ephemeral cert call registered
			wantErr: &errtype.RefreshError{},
			desc:    "When the CreateEphemeralCert call fails",
		},
		{
			reqs: []*mock.Request{mock.InstanceGetSuccess(inst, 1),
				mock.CreateEphemeralSuccess(
					mock.NewFakeCSQLInstance(cn.project, cn.region, cn.name,
						mock.WithClientCertSigner(
							func(*x509.Certificate, *rsa.PrivateKey, *rsa.PublicKey) ([]byte, error) {
								return nil, nil
							}),
					), 1),
			},
			wantErr: &errtype.RefreshError{},
			desc:    "When decoding the cert fails", // SQL Admin API fail
		},
		{
			reqs: []*mock.Request{mock.InstanceGetSuccess(inst, 1),
				mock.CreateEphemeralSuccess(
					mock.NewFakeCSQLInstance(cn.project, cn.region, cn.name,
						mock.WithClientCertSigner(
							func(*x509.Certificate, *rsa.PrivateKey, *rsa.PublicKey) ([]byte, error) {
								certPEM := &bytes.Buffer{}
								pem.Encode(certPEM, &pem.Block{
									Type:  "CERTIFICATE",
									Bytes: []byte("hello"), // woops no cert
								})
								return certPEM.Bytes(), nil
							}),
					), 1),
			},
			wantErr: &errtype.RefreshError{},
			desc:    "When parsing the cert fails", // SQL Admin API fail
		},
	}
	for i, tc := range testCases {
		client, cleanup, err := mock.NewSQLAdminService(
			context.Background(),
			tc.reqs...,
		)
		if err != nil {
			t.Fatalf("failed to create test SQL admin service: %s", err)
		}
		defer cleanup()

		r := newRefresher(client, nil, testDialerID)
		_, err = r.performRefresh(context.Background(), cn, RSAKey, false)

		if !errors.As(err, &tc.wantErr) {
			t.Errorf("[%v] PerformRefresh failed with unexpected error, want = %T, got = %v", i, tc.wantErr, err)
		}
	}
}

func TestRefreshBuildsTLSConfig(t *testing.T) {
	wantServerName := "my-project:my-region:my-instance"
	cn, _ := ParseConnName(wantServerName)
	inst := mock.NewFakeCSQLInstance(cn.project, cn.region, cn.name)
	certBytes, err := mock.SelfSign(inst.Cert, inst.Key)
	if err != nil {
		t.Fatalf("failed to sign certificate: %v", err)
	}
	client, cleanup, err := mock.NewSQLAdminService(
		context.Background(),
		mock.InstanceGetSuccess(inst, 1), // no server cert
		mock.CreateEphemeralSuccess(inst, 1),
	)
	if err != nil {
		t.Fatalf("failed to create test SQL admin service: %s", err)
	}
	defer cleanup()

	r := newRefresher(client, nil, testDialerID)
	rr, err := r.performRefresh(context.Background(), cn, RSAKey, false)
	if err != nil {
		t.Fatalf("expected no error, got = %v", err)
	}

	if wantServerName != rr.conf.ServerName {
		t.Fatalf(
			"TLS config has incorrect server name, want = %v, got = %v",
			wantServerName, rr.conf.ServerName,
		)
	}

	wantCertLen := 1
	if wantCertLen != len(rr.conf.Certificates) {
		t.Fatalf(
			"TLS config has unexpected number of certificates, want = %v, got = %v",
			wantCertLen, len(rr.conf.Certificates),
		)
	}

	wantInsecure := true
	if wantInsecure != rr.conf.InsecureSkipVerify {
		t.Fatalf(
			"TLS config should skip verification, want = %v, got = %v",
			wantInsecure, rr.conf.InsecureSkipVerify,
		)
	}

	if rr.conf.RootCAs == nil {
		t.Fatal("TLS config should include RootCA, got nil")
	}

	verifyPeerCert := rr.conf.VerifyPeerCertificate
	b, _ := pem.Decode(certBytes)
	err = verifyPeerCert([][]byte{b.Bytes}, nil)
	if err != nil {
		t.Fatalf("expected to verify peer cert, got error: %v", err)
	}

	err = verifyPeerCert(nil, nil)
	var wantErr *errtype.DialError
	if !errors.As(err, &wantErr) {
		t.Fatalf("when verify peer cert fails, want = %T, got = %v", wantErr, err)
	}

	err = verifyPeerCert([][]byte{[]byte("not a cert")}, nil)
	if !errors.As(err, &wantErr) {
		t.Fatalf("when verify fails on invalid cert, want = %T, got = %v", wantErr, err)
	}

	badCert := mock.GenerateCertWithCommonName(inst, "wrong:wrong")
	err = verifyPeerCert([][]byte{badCert}, nil)
	if !errors.As(err, &wantErr) {
		t.Fatalf("when common names mismatch, want = %T, got = %v", wantErr, err)
	}

	other := mock.NewFakeCSQLInstance(cn.project, cn.region, cn.name)
	certBytes, err = mock.SelfSign(other.Cert, other.Key)
	if err != nil {
		t.Fatalf("failed to sign certificate: %v", err)
	}
	b, _ = pem.Decode(certBytes)
	err = verifyPeerCert([][]byte{b.Bytes}, nil)
	if !errors.As(err, &wantErr) {
		t.Fatalf("when certification fails, want = %T, got = %v", wantErr, err)
	}
}
