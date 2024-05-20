// Copyright 2021 Google LLC
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

package cloudsqlconn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/cloudsqlconn/errtype"
	"cloud.google.com/go/cloudsqlconn/instance"
	"cloud.google.com/go/cloudsqlconn/internal/cloudsql"
	"cloud.google.com/go/cloudsqlconn/internal/mock"
	"golang.org/x/oauth2"
)

// testSuccessfulDial uses the provided dialer to dial the specified instance
// and verifies the connection works end to end.
func testSuccessfulDial(
	ctx context.Context, t *testing.T, d *Dialer, icn string, opts ...DialOption,
) {
	conn, err := d.Dial(ctx, icn, opts...)
	if err != nil {
		t.Fatalf("expected Dial to succeed, but got error: %v", err)
	}
	defer func() { _ = conn.Close() }()

	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("expected ReadAll to succeed, got error %v", err)
	}
	if string(data) != "my-instance" {
		t.Fatalf(
			"expected known response from the server, but got %v",
			string(data),
		)
	}
}

// setupConfig holds all the configuration to use when setting up a dialer.
type setupConfig struct {
	testInstance  mock.FakeCSQLInstance
	skipServer    bool
	skipVerify    bool
	reqs          []*mock.Request
	dialerOptions []Option
}

// setupDialer configures a Dialer with an HTTP client configured to point at a
// mock SQL Admin API. Use setupConfig to configure the expected requests.
func setupDialer(t *testing.T, c setupConfig) *Dialer {
	svc, cleanup, err := mock.NewSQLAdminService(
		context.Background(),
		c.reqs...,
	)
	if err != nil {
		t.Fatalf("failed to init SQLAdminService: %v", err)
	}
	stop := func() {}
	if !c.skipServer {
		stop = mock.StartServerProxy(t, c.testInstance)
	}
	t.Cleanup(func() {
		stop()
		err := cleanup()
		if !c.skipVerify && err != nil {
			t.Fatalf("%v", err)
		}
	})

	opts := []Option{
		WithTokenSource(mock.EmptyTokenSource{}),
		// give refresh plenty of time to complete in slower CI builds
		WithRefreshTimeout(time.Minute),
	}
	if c.dialerOptions != nil {
		opts = c.dialerOptions
	}

	d, err := NewDialer(context.Background(), opts...)
	if err != nil {
		t.Fatalf("expected NewDialer to succeed, but got error: %v", err)
	}
	d.sqladmin = svc
	return d
}

func TestDialerCanConnectToInstance(t *testing.T) {
	inst := mock.NewFakeCSQLInstance(
		"my-project", "my-region", "my-instance",
	)
	d := setupDialer(t, setupConfig{
		testInstance: inst,
		reqs: []*mock.Request{
			mock.InstanceGetSuccess(inst, 1),
			mock.CreateEphemeralSuccess(inst, 1),
		},
	})

	testSuccessfulDial(
		context.Background(), t, d,
		inst.String(),
	)
}

func TestDialWithAdminAPIErrors(t *testing.T) {
	inst := mock.NewFakeCSQLInstance(
		"my-project", "my-region", "my-instance",
	)
	// API server will respond with 40x's
	d := setupDialer(t, setupConfig{testInstance: inst})

	_, err := d.Dial(
		context.Background(), inst.String(),
	)
	var wantErr *errtype.RefreshError
	if !errors.As(err, &wantErr) {
		t.Fatalf("when API call fails, want = %T, got = %v", wantErr, err)
	}
}

func TestDialWithConfigurationErrors(t *testing.T) {
	inst := mock.NewFakeCSQLInstance(
		"my-project", "my-region", "my-instance",
	)
	d := setupDialer(t, setupConfig{
		testInstance: inst,
		reqs: []*mock.Request{
			mock.InstanceGetSuccess(inst, 3),
			mock.CreateEphemeralSuccess(inst, 3),
		},
		skipVerify: true,
		skipServer: true,
	})

	_, err := d.Dial(
		context.Background(),
		// Try private IP of a public IP-only instance
		inst.String(), WithPrivateIP(),
	)
	if err == nil {
		t.Fatal("when IP type is invalid, want = error, got = nil")
	}

	_, err = d.Dial(
		context.Background(), inst.String(),
	)
	if err == nil {
		t.Fatal("when server proxy socket is unavailable, want = error, got = nil")
	}
}

func TestDialWithExpiredCertificate(t *testing.T) {
	inst := mock.NewFakeCSQLInstance(
		"my-project", "my-region", "my-instance",
		// Server certificate is expired
		mock.WithCertExpiry(time.Now().Add(-time.Hour)),
	)
	d := setupDialer(t, setupConfig{
		testInstance: inst,
		reqs: []*mock.Request{
			mock.InstanceGetSuccess(inst, 3),
			mock.CreateEphemeralSuccess(inst, 3),
		},
		skipVerify: true,
		skipServer: true,
	})

	_, err := d.Dial(context.Background(), inst.String())
	if err == nil {
		t.Fatal("when TLS handshake fails, want = error, got = nil")
	}
}

func fakeServiceAccount(ud string) []byte {
	sa := `
		"type": "service_account",
		"project_id": "a-project-id",
		"private_key_id": "a-private-key-id",
		"private_key": "a-private-key",
		"client_email": "email@example.com",
		"client_id": "12345",
		"auth_uri": "https://accounts.google.com/o/oauth2/auth",
		"token_uri": "https://oauth2.googleapis.com/token",
		"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
		"client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/email%40example.com"
	`
	if ud != "" {
		sa = sa + fmt.Sprintf(`, "universe_domain": "%s"`, ud)
	}
	return []byte(fmt.Sprintf(`{ %s }`, sa))
}

func TestIAMAuthn(t *testing.T) {
	tcs := []struct {
		desc         string
		opts         Option
		wantIAMAuthN bool
	}{
		{
			desc: "When Credentials are provided with IAM Authn ENABLED",
			opts: WithOptions(
				WithIAMAuthN(),
				WithCredentialsJSON(fakeServiceAccount("")),
			),
			wantIAMAuthN: true,
		},
		{
			desc:         "When Credentials are provided with IAM Authn DISABLED",
			opts:         WithCredentialsJSON(fakeServiceAccount("")),
			wantIAMAuthN: false,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			d, err := NewDialer(context.Background(), tc.opts)
			if err != nil {
				t.Fatalf("NewDialer failed with error = %v", err)
			}
			if gotIAMAuthN := d.defaultDialConfig.useIAMAuthN; gotIAMAuthN != tc.wantIAMAuthN {
				t.Fatalf("want = %v, got = %v", tc.wantIAMAuthN, gotIAMAuthN)
			}
		})
	}
}

func TestSQLServerFailsOnIAMAuthN(t *testing.T) {
	inst := mock.NewFakeCSQLInstance("proj", "region", "inst",
		mock.WithEngineVersion("SQLSERVER"),
	)
	d := setupDialer(t, setupConfig{
		testInstance: inst,
		reqs: []*mock.Request{
			mock.InstanceGetSuccess(inst, 1),
			mock.CreateEphemeralSuccess(inst, 1),
		},
		dialerOptions: []Option{
			WithIAMAuthNTokenSources(
				mock.EmptyTokenSource{},
				mock.EmptyTokenSource{},
			), WithIAMAuthN(),
		},
		skipVerify: true,
	})

	_, err := d.Dial(context.Background(), inst.String())
	if err == nil {
		t.Fatalf("version = %v, want error, got nil", "SQLSERVER")
	}
}

func TestUniverseDomain(t *testing.T) {
	tcs := []struct {
		desc string
		opts Option
	}{
		{
			desc: "When universe domain matches GDU",
			opts: WithOptions(
				WithUniverseDomain("googleapis.com"),
				WithCredentialsJSON(fakeServiceAccount("")),
			),
		},
		{
			desc: "When TPC universe matches TPC credential domain",
			opts: WithOptions(
				WithUniverseDomain("test-universe.test"),
				WithCredentialsJSON(fakeServiceAccount("test-universe.test")),
			),
		},
	}

	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			_, err := NewDialer(context.Background(), tc.opts)
			if err != nil {
				t.Fatalf("NewDialer failed with error = %v", err)
			}
		})
	}
}

func TestUniverseDomainErrors(t *testing.T) {
	tcs := []struct {
		desc string
		opts Option
	}{
		{
			desc: "When universe domain does not match ADC credentials from GDU",
			opts: WithOptions(WithUniverseDomain("test-universe.test")),
		},
		{
			desc: "When GDU does not match credential domain",
			opts: WithOptions(WithCredentialsJSON(
				fakeServiceAccount("test-universe.test"),
			)),
		},
		{
			desc: "WithUniverseDomain used alongside WithAdminAPIEndpoint",
			opts: WithOptions(
				WithUniverseDomain("googleapis.com"),
				WithAdminAPIEndpoint("https://sqladmin.googleapis.com"),
			),
		},
	}

	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			_, err := NewDialer(context.Background(), tc.opts)
			t.Log(err)
			if err == nil {
				t.Fatalf("Wanted universe domain mismatch, want error, got nil")
			}
		})
	}
}

func TestDialerWithCustomDialFunc(t *testing.T) {
	inst := mock.NewFakeCSQLInstance("proj", "region", "inst",
		mock.WithEngineVersion("SQLSERVER"),
	)
	d := setupDialer(t, setupConfig{
		testInstance: inst,
		reqs: []*mock.Request{
			mock.InstanceGetSuccess(inst, 1),
			mock.CreateEphemeralSuccess(inst, 1),
		},
		dialerOptions: []Option{
			WithTokenSource(mock.EmptyTokenSource{}),
			WithDialFunc(func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("sentinel error")
			}),
		},
	})

	_, err := d.Dial(context.Background(), inst.String())
	if !strings.Contains(err.Error(), "sentinel error") {
		t.Fatalf("want = sentinel error, got = %v", err)
	}
}

func TestDialerEngineVersion(t *testing.T) {
	tests := []string{
		"MYSQL_5_7", "POSTGRES_14", "SQLSERVER_2019_STANDARD", "MYSQL_8_0_18",
	}
	for _, wantEV := range tests {
		t.Run(wantEV, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			inst := mock.NewFakeCSQLInstance(
				"my-project", "my-region", "my-instance",
				mock.WithEngineVersion(wantEV),
			)
			d := setupDialer(t, setupConfig{
				testInstance: inst,
				reqs: []*mock.Request{
					mock.InstanceGetSuccess(inst, 1),
					mock.CreateEphemeralSuccess(inst, 1),
				},
				dialerOptions: []Option{
					WithTokenSource(mock.EmptyTokenSource{}),
				},
			})

			gotEV, err := d.EngineVersion(ctx, inst.String())
			if err != nil {
				t.Fatalf("failed to retrieve engine version: %v", err)
			}
			if wantEV != gotEV {
				t.Errorf(
					"InstanceEngineVersion(%s) failed: want %v, got %v",
					wantEV, gotEV, err,
				)
			}
		})
	}
}

// When Auto IAM AuthN is enabled, EngineVersion should warm the cache with a
// client certificate with Auto IAM AuthN enabled.
func TestEngineVersionAvoidsDuplicateRefreshWithIAMAuthN(t *testing.T) {
	inst := mock.NewFakeCSQLInstance(
		"my-project", "my-region", "my-instance",
	)
	d := setupDialer(t, setupConfig{
		testInstance: inst,
		dialerOptions: []Option{
			WithIAMAuthN(), WithIAMAuthNTokenSources(
				mock.EmptyTokenSource{},
				mock.EmptyTokenSource{},
			),
		},
		reqs: []*mock.Request{
			// There should only be two API requests
			mock.InstanceGetSuccess(inst, 1),
			mock.CreateEphemeralSuccess(inst, 1),
		},
	})

	_, err := d.EngineVersion(context.Background(), inst.String())
	if err != nil {
		t.Fatal(err)
	}

	testSuccessfulDial(
		context.Background(), t, d,
		inst.String(),
	)
}

func TestDialerUserAgent(t *testing.T) {
	data, err := os.ReadFile("version.txt")
	if err != nil {
		t.Fatalf("failed to read version.txt: %v", err)
	}
	ver := strings.TrimSpace(string(data))
	want := "cloud-sql-go-connector/" + ver
	if want != userAgent {
		t.Errorf("embed version mismatched: want %q, got %q", want, userAgent)
	}
}

func TestWarmup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	inst := mock.NewFakeCSQLInstance("my-project", "my-region", "my-instance")
	tests := []struct {
		desc          string
		warmupOpts    []DialOption
		dialOpts      []DialOption
		expectedCalls []*mock.Request
	}{
		{
			desc:       "Warmup and Dial both use IAM AuthN",
			warmupOpts: []DialOption{WithDialIAMAuthN(true)},
			dialOpts:   []DialOption{WithDialIAMAuthN(true)},
			expectedCalls: []*mock.Request{
				mock.InstanceGetSuccess(inst, 1),
				mock.CreateEphemeralSuccess(inst, 1),
			},
		},
		{
			desc:       "Warmup uses IAM Authn, Dial does not",
			warmupOpts: []DialOption{WithDialIAMAuthN(true)},
			dialOpts:   []DialOption{WithDialIAMAuthN(false)},
			expectedCalls: []*mock.Request{
				mock.InstanceGetSuccess(inst, 2),
				mock.CreateEphemeralSuccess(inst, 2),
			},
		},
		{
			desc:       "Warmup uses IAM AuthN, Dial uses global setting",
			warmupOpts: []DialOption{WithDialIAMAuthN(true)},
			dialOpts:   []DialOption{},
			expectedCalls: []*mock.Request{
				mock.InstanceGetSuccess(inst, 1),
				mock.CreateEphemeralSuccess(inst, 1),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			d := setupDialer(t, setupConfig{
				dialerOptions: []Option{
					WithIAMAuthN(),
					WithIAMAuthNTokenSources(
						mock.EmptyTokenSource{},
						mock.EmptyTokenSource{},
					),
				},
				testInstance: inst,
				reqs:         test.expectedCalls,
			})

			// Warmup once with the "default" options
			err := d.Warmup(ctx, inst.String(), test.warmupOpts...)
			if err != nil {
				t.Fatalf("Warmup failed: %v", err)
			}
			// Call EngineVersion to make sure we block until both API calls
			// are completed.
			_, err = d.EngineVersion(ctx, inst.String())
			if err != nil {
				t.Fatalf("Warmup failed: %v", err)
			}
			// Dial once with the "dial" options
			testSuccessfulDial(
				ctx, t, d,
				inst.String(),
				test.dialOpts...,
			)
		})
	}
}

func TestDialDialerOptsConflicts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	inst := mock.NewFakeCSQLInstance("my-project", "my-region", "my-instance")
	tests := []struct {
		desc          string
		dialerOpts    []Option
		dialOpts      []DialOption
		expectedCalls []*mock.Request
	}{
		{
			desc:       "dialer opts set and dial uses default",
			dialerOpts: []Option{WithIAMAuthN()},
			dialOpts:   []DialOption{},
			expectedCalls: []*mock.Request{
				mock.InstanceGetSuccess(inst, 1),
				mock.CreateEphemeralSuccess(inst, 1),
			},
		},
		{
			desc:       "dialer and dial opts are the same",
			dialerOpts: []Option{WithIAMAuthN()},
			dialOpts:   []DialOption{WithDialIAMAuthN(true)},
			expectedCalls: []*mock.Request{
				mock.InstanceGetSuccess(inst, 1),
				mock.CreateEphemeralSuccess(inst, 1),
			},
		},
		{
			desc:       "dialer and dial opts are different",
			dialerOpts: []Option{WithIAMAuthN()},
			dialOpts:   []DialOption{WithDialIAMAuthN(false)},
			expectedCalls: []*mock.Request{
				mock.InstanceGetSuccess(inst, 2),
				mock.CreateEphemeralSuccess(inst, 2),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			d := setupDialer(t, setupConfig{
				testInstance: inst,
				reqs:         tc.expectedCalls,
				dialerOptions: append(
					tc.dialerOpts,
					WithIAMAuthNTokenSources(
						mock.EmptyTokenSource{}, mock.EmptyTokenSource{},
					),
				),
			})

			// Dial once with the "default" options
			testSuccessfulDial(ctx, t, d, inst.String())

			// Dial once with the "dial" options
			testSuccessfulDial(ctx, t, d, inst.String(), tc.dialOpts...)
		})
	}
}

func TestTokenSourceWithIAMAuthN(t *testing.T) {
	ts := oauth2.StaticTokenSource(&oauth2.Token{})
	tcs := []struct {
		desc    string
		opts    []Option
		wantErr bool
	}{
		{
			desc:    "when token source is set with IAM AuthN",
			opts:    []Option{WithTokenSource(ts), WithIAMAuthN()},
			wantErr: true,
		},
		{
			desc:    "when IAM AuthN token source is set without IAM AuthN",
			opts:    []Option{WithIAMAuthNTokenSources(ts, ts)},
			wantErr: true,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			_, err := NewDialer(context.Background(), tc.opts...)
			gotErr := err != nil
			if tc.wantErr != gotErr {
				t.Fatalf("err: want = %v, got = %v", tc.wantErr, gotErr)
			}
		})
	}
}

func TestDialerRemovesInvalidInstancesFromCache(t *testing.T) {
	// When a dialer attempts to retrieve connection info for a
	// non-existent instance, it should delete the instance from
	// the cache and ensure no background refresh happens (which would be
	// wasted cycles).
	d, err := NewDialer(
		context.Background(),
		WithTokenSource(mock.EmptyTokenSource{}),
	)
	if err != nil {
		t.Fatalf("expected NewDialer to succeed, but got error: %v", err)
	}

	// Populate instance map with connection info cache that will always fail
	// This allows the test to verify the error case path invoking close.
	badInstanceConnectionName := "doesntexist:us-central1:doesntexist"
	badCN, _ := instance.ParseConnName(badInstanceConnectionName)
	spy := &spyConnectionInfoCache{
		connectInfoCalls: []struct {
			info cloudsql.ConnectionInfo
			err  error
		}{{
			err: errors.New("connect info failed"),
		}},
	}
	d.cache[badCN] = monitoredCache{connectionInfoCache: spy}

	_, err = d.Dial(context.Background(), badInstanceConnectionName)
	if err == nil {
		t.Fatal("expected Dial to return error")
	}

	// Verify that the connection info cache was closed (to prevent
	// further failed refresh operations)
	if got, want := spy.CloseWasCalled(), true; got != want {
		t.Fatal("Close was not called")
	}

	// Now verify that bad connection name has been deleted from map.
	d.lock.RLock()
	_, ok := d.cache[badCN]
	d.lock.RUnlock()
	if ok {
		t.Fatal("bad instance was not removed from the cache")
	}
}

func TestDialRefreshesExpiredCertificates(t *testing.T) {
	d, err := NewDialer(context.Background(),
		WithTokenSource(mock.EmptyTokenSource{}),
	)
	if err != nil {
		t.Fatalf("expected NewDialer to succeed, but got error: %v", err)
	}

	sentinel := errors.New("connect info failed")
	icn := "project:region:instance"
	cn, _ := instance.ParseConnName(icn)
	spy := &spyConnectionInfoCache{
		connectInfoCalls: []struct {
			info cloudsql.ConnectionInfo
			err  error
		}{
			// First call returns expired certificate
			{
				// Certificate expired 10 hours ago.
				info: cloudsql.ConnectionInfo{
					Expiration: time.Now().Add(-10 * time.Hour),
				},
			},
			// Second call errors to validate error path
			{
				err: sentinel,
			},
		},
	}
	d.cache[cn] = monitoredCache{connectionInfoCache: spy}

	_, err = d.Dial(context.Background(), icn)
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected Dial to return sentinel error, instead got = %v", err)
	}

	// Verify that the cache was refreshed
	if got, want := spy.ForceRefreshWasCalled(), true; got != want {
		t.Fatal("ForceRefresh was not called")
	}

	// Verify that the connection info cache was closed (to prevent
	// further failed refresh operations)
	if got, want := spy.CloseWasCalled(), true; got != want {
		t.Fatal("Close was not called")
	}

	// Now verify that bad connection name has been deleted from map.
	d.lock.RLock()
	_, ok := d.cache[cn]
	d.lock.RUnlock()
	if ok {
		t.Fatal("bad instance was not removed from the cache")
	}

}

type spyConnectionInfoCache struct {
	mu               sync.Mutex
	connectInfoIndex int
	connectInfoCalls []struct {
		info cloudsql.ConnectionInfo
		err  error
	}
	closeWasCalled        bool
	forceRefreshWasCalled bool
	// embed interface to avoid having to implement irrelevant methods
	connectionInfoCache
}

func (s *spyConnectionInfoCache) ConnectionInfo(
	context.Context,
) (cloudsql.ConnectionInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res := s.connectInfoCalls[s.connectInfoIndex]
	s.connectInfoIndex++
	return res.info, res.err
}

func (s *spyConnectionInfoCache) ForceRefresh() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forceRefreshWasCalled = true
}

func (s *spyConnectionInfoCache) UpdateRefresh(*bool) {}

func (s *spyConnectionInfoCache) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeWasCalled = true
	return nil
}

func (s *spyConnectionInfoCache) CloseWasCalled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeWasCalled
}

func (s *spyConnectionInfoCache) ForceRefreshWasCalled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.forceRefreshWasCalled
}

func TestDialerSupportsOneOffDialFunction(t *testing.T) {
	ctx := context.Background()
	inst := mock.NewFakeCSQLInstance("p", "r", "i")
	svc, cleanup, err := mock.NewSQLAdminService(
		context.Background(),
		mock.InstanceGetSuccess(inst, 1),
		mock.CreateEphemeralSuccess(inst, 1),
	)
	if err != nil {
		t.Fatalf("failed to init SQLAdminService: %v", err)
	}
	d, err := NewDialer(ctx, WithTokenSource(mock.EmptyTokenSource{}))
	if err != nil {
		t.Fatal(err)
	}
	d.sqladmin = svc
	defer func() {
		if err := d.Close(); err != nil {
			t.Log(err)
		}
		_ = cleanup()
	}()

	sentinelErr := errors.New("dial func was called")
	f := func(context.Context, string, string) (net.Conn, error) {
		return nil, sentinelErr
	}

	if _, err := d.Dial(ctx, "p:r:i", WithOneOffDialFunc(f)); !errors.Is(err, sentinelErr) {
		t.Fatal("one-off dial func was not called")
	}
}

func TestDialerCloseReportsFriendlyError(t *testing.T) {
	d, err := NewDialer(
		context.Background(),
		WithTokenSource(mock.EmptyTokenSource{}),
	)
	if err != nil {
		t.Fatal(err)
	}
	_ = d.Close()

	_, err = d.Dial(context.Background(), "p:r:i")
	if !errors.Is(err, ErrDialerClosed) {
		t.Fatalf("want = %v, got = %v", ErrDialerClosed, err)
	}

	// Ensure multiple calls to close don't panic
	_ = d.Close()

	_, err = d.Dial(context.Background(), "p:r:i")
	if !errors.Is(err, ErrDialerClosed) {
		t.Fatalf("want = %v, got = %v", ErrDialerClosed, err)
	}
}

func TestDialerInitializesLazyCache(t *testing.T) {
	cn, _ := instance.ParseConnName("my-project:my-region:my-instance")
	inst := mock.NewFakeCSQLInstance(
		cn.Project(), cn.Region(), cn.Name(),
	)
	d := setupDialer(t, setupConfig{
		testInstance: inst,
		reqs: []*mock.Request{
			mock.InstanceGetSuccess(inst, 1),
			mock.CreateEphemeralSuccess(inst, 1),
		},
		dialerOptions: []Option{
			WithTokenSource(mock.EmptyTokenSource{}),
			WithLazyRefresh(),
		},
	})

	// Initialize the connection info cache
	_, err := d.Dial(context.Background(), inst.String())
	if err != nil {
		t.Fatal(err)
	}

	c, ok := d.cache[cn]
	if !ok {
		t.Fatal("cache was not populated")
	}
	switch tt := c.connectionInfoCache.(type) {
	case *cloudsql.LazyRefreshCache:
		// Pass -- the cache was initialized with the correct type
	default:
		t.Fatalf("dialer was initialized with non-lazy type: %T", tt)
	}
}
