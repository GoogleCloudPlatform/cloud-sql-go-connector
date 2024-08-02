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
	wantPSC := true
	wantDNS := "abcde.12345.us-central1.sql.goog"
	wantExpiry := time.Now().Add(time.Hour).UTC().Round(time.Second)
	cn := testInstanceConnName()
	inst := mock.NewFakeCSQLInstance(
		cn.Project(), cn.Region(), cn.Name(),
		mock.WithPublicIP(wantPublicIP),
		mock.WithPrivateIP(wantPrivateIP),
		mock.WithPSC(wantPSC),
		mock.WithDNS(wantDNS),
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

	r := newAdminAPIClient(nullLogger{}, client, RSAKey, nil, testDialerID)
	rr, err := r.ConnectionInfo(context.Background(), cn, false)
	if err != nil {
		t.Fatalf("PerformRefresh unexpectedly failed with error: %v", err)
	}

	gotIP, ok := rr.addrs[PublicIP]
	if !ok {
		t.Fatal("metadata IP addresses did not include public address")
	}
	if wantPublicIP != gotIP {
		t.Fatalf("metadata IP mismatch, want = %v, got = %v", wantPublicIP, gotIP)
	}
	gotIP, ok = rr.addrs[PrivateIP]
	if !ok {
		t.Fatal("metadata IP addresses did not include private address")
	}
	if wantPrivateIP != gotIP {
		t.Fatalf("metadata IP mismatch, want = %v, got = %v", wantPrivateIP, gotIP)
	}
	gotDNS, ok := rr.addrs[PSC]
	if !ok {
		t.Fatal("metadata IP addresses did not include PSC endpoint")
	}
	if wantDNS != gotDNS {
		t.Fatalf("metadata IP mismatch, want = %v. got = %v", wantPSC, gotPSC)
	}
	if cn != rr.ConnectionName {
		t.Fatalf(
			"connection name mismatch, want = %v, got = %v",
			cn.Name(), rr.ConnectionName,
		)
	}
	if wantExpiry != rr.Expiration {
		t.Fatalf("expiry mismatch, want = %v, got = %v", wantExpiry, rr.Expiration)
	}
}

func TestRefreshForCASInstances(t *testing.T) {
	wantDNS := "abcde.12345.us-central1.sql.goog"
	cn := testInstanceConnName()
	inst := mock.NewFakeCSQLInstance(
		cn.Project(), cn.Region(), "",
		mock.WithPublicIP("127.0.0.1"),
		mock.WithServerCAMode("GOOGLE_MANAGED_CAS_CA"),
		mock.WithDNS(wantDNS),
		mock.WithCertExpiry(time.Now().Add(time.Hour).UTC().Round(time.Second)),
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

	r := newAdminAPIClient(nullLogger{}, client, RSAKey, nil, testDialerID)
	rr, err := r.ConnectionInfo(context.Background(), cn, false)
	if err != nil {
		t.Fatalf("PerformRefresh unexpectedly failed with error: %v", err)
	}

	if wantDNS != rr.DNSName {
		t.Fatalf("metadata IP mismatch, want = %v. got = %v", wantPSC, gotPSC)
	}
	if rr.ConnectionName != "" {
		t.Fatalf(
			"connection name mismatch, want empty, got = %v",
			cn.Name(),
		)
	}
	if rr.ServerCaMode != "GOOGLE_MANAGED_CAS_CA" {
		t.Fatalf("server CA mode mismatch, want = GOOGLE_MANAGED_CAS_CA, got = %v", rr.ServerCaMode)
	}
	if len(rr.ServerCaCertPem) == 0 {
		t.Fatalf("server cert pem mismatch, want not empty, got empty")
	}
}

// If a caller has provided a static token source that cannot be refreshed
// (e.g., when the Cloud SQL Proxy is invokved with --token), then the
// refresher cannot determine the token's expiration (without additional API
// calls), and so the refresher should use the certificate's expiration instead
// of the token's expiration which is otherwise unset.
func TestRefreshWithStaticTokenSource(t *testing.T) {
	cn := testInstanceConnName()
	inst := mock.NewFakeCSQLInstance(
		cn.Project(), cn.Region(), cn.Name(),
	)
	client, cleanup, err := mock.NewSQLAdminService(
		context.Background(),
		mock.InstanceGetSuccess(inst, 1),
		mock.CreateEphemeralSuccess(inst, 1),
	)
	if err != nil {
		t.Fatalf("failed to create test SQL admin service: %s", err)
	}
	t.Cleanup(func() { _ = cleanup() })

	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "myaccestoken"})
	r := newAdminAPIClient(nullLogger{}, client, RSAKey, ts, testDialerID)
	ci, err := r.ConnectionInfo(context.Background(), cn, true)
	if err != nil {
		t.Fatalf("PerformRefresh unexpectedly failed with error: %v", err)
	}
	if !ci.Expiration.After(time.Now()) {
		t.Fatalf(
			"Connection info expiration should be in the future, got = %v",
			ci.Expiration,
		)
	}
}

func TestRefreshRetries50xResponses(t *testing.T) {
	cn := testInstanceConnName()
	inst := mock.NewFakeCSQLInstance(cn.Project(), cn.Region(), cn.Name(),
		mock.WithEngineVersion("WANTED_VERSION"),
	)
	client, cleanup, err := mock.NewSQLAdminService(
		context.Background(),
		// First a 500, then a 200 response
		mock.InstanceGet500(inst, 1),
		mock.InstanceGetSuccess(inst, 1),
		// First a 500, then a 200 response
		mock.CreateEphemeral500(inst, 1),
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

	r := newAdminAPIClient(nullLogger{}, client, RSAKey, nil, testDialerID)
	rr, err := r.ConnectionInfo(context.Background(), cn, false)
	if err != nil {
		t.Fatalf("PerformRefresh unexpectedly failed with error: %v", err)
	}
	if rr.DBVersion != "WANTED_VERSION" {
		t.Fatalf("DB version did not match expected, got = %v, want = %v",
			rr.DBVersion, "WANTED_VERSION",
		)
	}
}

func TestRefreshFailsFast(t *testing.T) {
	cn := testInstanceConnName()
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

	r := newAdminAPIClient(nullLogger{}, client, RSAKey, nil, testDialerID)
	_, err = r.ConnectionInfo(context.Background(), cn, false)
	if err != nil {
		t.Fatalf("expected no error, got = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// context is canceled
	_, err = r.ConnectionInfo(ctx, cn, false)
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
	cn := testInstanceConnName()
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
			r := newAdminAPIClient(nullLogger{}, client, RSAKey, ts, testDialerID)
			rr, err := r.ConnectionInfo(context.Background(), cn, true)
			if err != nil {
				t.Fatalf("want no error, got = %v", err)
			}
			if tc.wantExpiry != rr.Expiration {
				t.Fatalf("want = %v, got = %v", tc.wantExpiry, rr.Expiration)
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
	cn := testInstanceConnName()
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
			r := newAdminAPIClient(nullLogger{}, client, RSAKey, ts, testDialerID)
			_, err := r.ConnectionInfo(context.Background(), cn, true)
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
	cn := testInstanceConnName()

	testCases := []struct {
		req     *mock.Request
		wantErr *errtype.ConfigError
		desc    string
	}{
		{
			req: mock.InstanceGetSuccess(
				mock.NewFakeCSQLInstance(
					cn.Project(), cn.Region(), cn.Name(),
					mock.WithRegion("my-region"),
					mock.WithFirstGenBackend(),
				), 1),
			wantErr: &errtype.ConfigError{},
			desc:    "When the instance isn't Second generation",
		},
		{
			req: mock.InstanceGetSuccess(
				mock.NewFakeCSQLInstance(cn.Project(), cn.Region(), cn.Name(),
					mock.WithRegion("some-other-region")), 1),
			wantErr: &errtype.ConfigError{},
			desc:    "When the region does not match",
		},
		{
			req: mock.InstanceGetSuccess(
				mock.NewFakeCSQLInstance(
					cn.Project(), cn.Region(), cn.Name(),
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

			r := newAdminAPIClient(nullLogger{}, client, RSAKey, nil, testDialerID)
			_, err = r.ConnectionInfo(context.Background(), cn, false)
			if !errors.As(err, &tc.wantErr) {
				t.Errorf("[%v] PerformRefresh failed with unexpected error, want = %T, got = %v", i, tc.wantErr, err)
			}
		})
	}
}

func TestRefreshMetadataRefreshError(t *testing.T) {
	cn := testInstanceConnName()

	testCases := []struct {
		req     *mock.Request
		wantErr *errtype.RefreshError
		desc    string
	}{
		{
			req: mock.CreateEphemeralSuccess(
				mock.NewFakeCSQLInstance(cn.Project(), cn.Region(), cn.Name()), 1),
			wantErr: &errtype.RefreshError{},
			desc:    "When the Metadata call fails",
		},
		{
			req: mock.InstanceGetSuccess(
				mock.NewFakeCSQLInstance(
					cn.Project(), cn.Region(), cn.Name(),
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
					cn.Project(), cn.Region(), cn.Name(),
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

			r := newAdminAPIClient(nullLogger{}, client, RSAKey, nil, testDialerID)
			_, err = r.ConnectionInfo(context.Background(), cn, false)
			if !errors.As(err, &tc.wantErr) {
				t.Errorf("[%v] PerformRefresh failed with unexpected error, want = %T, got = %v", i, tc.wantErr, err)
			}
		})
	}
}

func TestRefreshWithFailedEphemeralCertCall(t *testing.T) {
	cn := testInstanceConnName()
	inst := mock.NewFakeCSQLInstance(cn.Project(), cn.Region(), cn.Name())

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
					mock.NewFakeCSQLInstance(cn.Project(), cn.Region(), cn.Name(),
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
					mock.NewFakeCSQLInstance(cn.Project(), cn.Region(), cn.Name(),
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

		r := newAdminAPIClient(nullLogger{}, client, RSAKey, nil, testDialerID)
		_, err = r.ConnectionInfo(context.Background(), cn, false)

		if !errors.As(err, &tc.wantErr) {
			t.Errorf("[%v] PerformRefresh failed with unexpected error, want = %T, got = %v", i, tc.wantErr, err)
		}
	}
}
