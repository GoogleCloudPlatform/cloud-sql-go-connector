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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cloud.google.com/go/auth"
	"cloud.google.com/go/cloudsqlconn/errtype"
	"cloud.google.com/go/cloudsqlconn/instance"
	"cloud.google.com/go/cloudsqlconn/internal/cloudsql"
	"cloud.google.com/go/cloudsqlconn/internal/mdx"
	"cloud.google.com/go/cloudsqlconn/internal/mock"
	"cloud.google.com/go/cloudsqlconn/internal/tel"
	"cloud.google.com/go/monitoring/apiv3/v2/monitoringpb"
	"golang.org/x/oauth2"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
)

// TestMain turns built-in metrics off for the whole test process. The
// production default is on; without this, every NewDialer in the suite
// would create a Cloud Monitoring client and periodic exporters that try to
// reach the real API. Tests that exercise metrics pass
// WithBuiltInMetrics(true) explicitly, and TestBuiltInMetricsEnabledByDefault
// checks the production default.
func TestMain(m *testing.M) {
	builtInMetricsDefault = false
	os.Exit(m.Run())
}

// testSuccessfulDial uses the provided dialer to dial the specified instance
// and verifies the connection works end to end.
func testSuccessfulDial(
	ctx context.Context, t *testing.T, d *Dialer, icn string, opts ...DialOption,
) {
	testSucessfulDialWithInstanceName(ctx, t, d, icn, "my-instance", opts...)
}

// testSuccessfulDial uses the provided dialer to dial the specified instance
// and verifies the connection works end to end.
func testSucessfulDialWithInstanceName(
	ctx context.Context, t *testing.T, d *Dialer, icn string, instanceName string, opts ...DialOption,
) {
	conn, err := d.Dial(ctx, icn, opts...)
	if err != nil {
		t.Fatalf("expected Dial to succeed, but got error: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_, err = conn.Write([]byte("hello world"))
	if err != nil {
		t.Fatalf("expected ReadAll to succeed, got error %v", err)
	}

	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("expected ReadAll to succeed, got error %v %v", data, err)
	}
	if string(data) != instanceName {
		t.Fatalf(
			"expected known response from the server, but got %v",
			string(data),
		)
	}
}

// withMockDNSResolver replaces  net.DefaultResolver with a mock resolver
func withMockDNSResolver(r cloudsql.NetResolver) Option {
	return func(d *dialerConfig) {
		d.dnsResolver = r
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

func TestDialerCanConnectToInstanceWithMdx(t *testing.T) {
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
		WithMdxClientProtocolType(cloudsql.ClientProtocolTCP),
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
		t.Fatal("when CLIENT_PROTOCOL_TLS handshake fails, want = error, got = nil")
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

func TestEngineVersionRemovesInvalidInstancesFromCache(t *testing.T) {
	// When a dialer attempts to call EngineVersion for a
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
	tcs := []struct {
		desc string
		icn  string
		resp connectionInfoResp
		opts []DialOption
	}{
		{
			desc: "EngineVersion on a bad instance URI",
			icn:  badInstanceConnectionName,
			resp: connectionInfoResp{
				err: errors.New("connect info failed"),
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			// Manually populate the internal cache with a spy
			inst, _ := instance.ParseConnName(tc.icn)
			spy := &spyConnectionInfoCache{
				connectInfoCalls: []connectionInfoResp{tc.resp},
			}
			d.cache[createKey(inst)] = newMonitoredCache(spy, inst, 0, nil, nil)

			_, err = d.EngineVersion(context.Background(), tc.icn)
			if err == nil {
				t.Fatal("expected EngineVersion to return error")
			}
			// Verify that the connection info cache was closed (to prevent
			// further failed refresh operations)
			if got, want := spy.closeWasCalled(), true; got != want {
				t.Fatal("Close was not called")
			}

			// Now verify that bad connection name has been deleted from map.
			d.lock.RLock()
			_, ok := d.cache[createKey(inst)]
			d.lock.RUnlock()
			if ok {
				t.Fatal("connection info was not removed from cache")
			}
		})
	}
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

func TestWarmupRemovesInvalidInstancesFromCache(t *testing.T) {
	// When a dialer attempts to Warmup for a non-existent instance,
	// it should delete the instance from the cache and ensure no background
	// refresh happens (which would be wasted cycles).
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
	tcs := []struct {
		desc string
		icn  string
		resp connectionInfoResp
		opts []DialOption
	}{
		{
			desc: "warmup a bad instance URI",
			icn:  badInstanceConnectionName,
			resp: connectionInfoResp{
				err: errors.New("connect info failed"),
			},
			opts: []DialOption{WithDialIAMAuthN(true)},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			// Manually populate the internal cache with a spy
			inst, _ := instance.ParseConnName(tc.icn)
			spy := &spyConnectionInfoCache{
				connectInfoCalls: []connectionInfoResp{tc.resp},
			}
			d.cache[createKey(inst)] = newMonitoredCache(spy, inst, 0, nil, nil)

			err = d.Warmup(context.Background(), tc.icn, tc.opts...)
			if err == nil {
				t.Fatal("expected Warmup to return error")
			}
			// Verify that the connection info cache was closed (to prevent
			// further failed refresh operations)
			if got, want := spy.closeWasCalled(), true; got != want {
				t.Fatal("Close was not called")
			}

			// Now verify that bad connection name has been deleted from map.
			d.lock.RLock()
			_, ok := d.cache[createKey(inst)]
			d.lock.RUnlock()
			if ok {
				t.Fatal("connection info was not removed from cache")
			}
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

func TestCredentialsWithIAMAuthN(t *testing.T) {
	ts := &auth.Credentials{}
	tcs := []struct {
		desc    string
		opts    []Option
		wantErr bool
	}{
		{
			desc:    "when token source is set with IAM AuthN",
			opts:    []Option{WithCredentials(ts), WithIAMAuthN()},
			wantErr: true,
		},
		{
			desc:    "when IAM AuthN token source is set without IAM AuthN",
			opts:    []Option{WithIAMAuthNCredentials(ts, ts)},
			wantErr: true,
		},
		{
			desc:    "when IAM AuthN token source is set with IAM AuthN",
			opts:    []Option{WithIAMAuthNCredentials(ts, ts), WithIAMAuthN()},
			wantErr: false,
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
	tcs := []struct {
		desc string
		icn  string
		resp connectionInfoResp
		opts []DialOption
	}{
		{
			desc: "dialing a bad instance URI",
			icn:  badInstanceConnectionName,
			resp: connectionInfoResp{
				err: errors.New("connect info failed"),
			},
		},
		{
			desc: "specifying an invalid IP type",
			icn:  "myproject:myregion:myinstance",
			resp: connectionInfoResp{
				info: cloudsql.NewConnectionInfo(
					instance.ConnName{},
					"",
					"GOOGLE_MANAGED_INTERNAL_CA",
					"",
					map[string][]string{
						// no public IP
						cloudsql.PrivateIP: {"10.0.0.1"},
					},
					nil,
					tls.Certificate{Leaf: &x509.Certificate{
						NotAfter: time.Now().Add(time.Hour),
					}},
					nil,
				),
			},
			opts: []DialOption{WithPublicIP()},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			// Manually populate the internal cache with a spy
			inst, _ := instance.ParseConnName(tc.icn)
			spy := &spyConnectionInfoCache{
				connectInfoCalls: []connectionInfoResp{tc.resp},
			}
			d.cache[createKey(inst)] = newMonitoredCache(spy, inst, 0, nil, nil)

			_, err = d.Dial(context.Background(), tc.icn, tc.opts...)
			if err == nil {
				t.Fatal("expected Dial to return error")
			}
			// Verify that the connection info cache was closed (to prevent
			// further failed refresh operations)
			if got, want := spy.closeWasCalled(), true; got != want {
				t.Fatal("Close was not called")
			}

			// Now verify that bad connection name has been deleted from map.
			d.lock.RLock()
			_, ok := d.cache[createKey(inst)]
			d.lock.RUnlock()
			if ok {
				t.Fatal("connection info was not removed from cache")
			}
		})
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
		connectInfoCalls: []connectionInfoResp{
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
	d.cache[createKey(cn)] = newMonitoredCache(spy, cn, 0, nil, nil)

	_, err = d.Dial(context.Background(), icn)
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected Dial to return sentinel error, instead got = %v", err)
	}

	// Verify that the cache was refreshed
	if got, want := spy.forceRefreshWasCalled(), true; got != want {
		t.Fatal("ForceRefresh was not called")
	}

	// Verify that the connection info cache was closed (to prevent
	// further failed refresh operations)
	if got, want := spy.closeWasCalled(), true; got != want {
		t.Fatal("Close was not called")
	}

	// Now verify that bad connection name has been deleted from map.
	d.lock.RLock()
	_, ok := d.cache[createKey(cn)]
	d.lock.RUnlock()
	if ok {
		t.Fatal("bad instance was not removed from the cache")
	}

}

type connectionInfoResp struct {
	info cloudsql.ConnectionInfo
	err  error
}

type spyConnectionInfoCache struct {
	mu               sync.Mutex
	connectInfoIndex int
	connectInfoCalls []connectionInfoResp

	closed         bool
	forceRefreshed bool
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
	s.forceRefreshed = true
}

func (s *spyConnectionInfoCache) UpdateRefresh(*bool) {}

func (s *spyConnectionInfoCache) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (s *spyConnectionInfoCache) closeWasCalled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *spyConnectionInfoCache) forceRefreshWasCalled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.forceRefreshed
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

// TestDialerIDIsUniquePerDialer guards the client_uid contract: every Dialer
// owns its own metric counters and export loop, so two Dialers in one
// process (e.g. an IAM and a non-IAM driver registered side by side) must
// report distinct client_uid values. A shared ID would make them write
// conflicting cumulative points to the same Cloud Monitoring series.
func TestDialerIDIsUniquePerDialer(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		d, err := NewDialer(
			context.Background(),
			WithTokenSource(mock.EmptyTokenSource{}),
		)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = d.Close() })
		id := d.dialerID
		if id == "" {
			t.Fatalf("dialer %d has an empty dialerID", i)
		}
		if seen[id] {
			t.Fatalf("dialer %d reused dialerID %q", i, id)
		}
		seen[id] = true
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

	c, ok := d.cache[createKey(cn)]
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

type mockNetResolver struct {
	txtEntries  map[string]string
	hostEntries map[string]string
}

func (r *mockNetResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if val, ok := r.txtEntries[name]; ok {
		return []string{val}, nil
	}
	return nil, fmt.Errorf("no resolution for %q", name)
}

func (r *mockNetResolver) LookupHost(_ context.Context, name string) ([]string, error) {
	if val, ok := r.hostEntries[name]; ok {
		return []string{val}, nil
	}
	return nil, fmt.Errorf("no resolution for %q", name)
}

func (r *mockNetResolver) LookupCNAME(_ context.Context, name string) (string, error) {
	return "", fmt.Errorf("no CNAME resolution for %q", name)
}

func TestDialerSuccessfullyDialsDnsTxtRecord(t *testing.T) {
	inst := mock.NewFakeCSQLInstance(
		"my-project", "my-region", "my-instance",
		mock.WithDNSMapping("db.example.com", "INSTANCE", "CUSTOM_SAN"),
		mock.WithDNSMapping("db2.example.com", "INSTANCE", "CUSTOM_SAN"),
	)
	// This will create 2 separate connectionInfoCache entries, one for
	// each DNS name.
	d := setupDialer(t, setupConfig{
		testInstance: inst,
		reqs: []*mock.Request{
			mock.InstanceGetSuccess(inst, 2),
			mock.CreateEphemeralSuccess(inst, 2),
		},
		dialerOptions: []Option{
			withMockDNSResolver(&mockNetResolver{
				txtEntries: map[string]string{
					"db.example.com":  "my-project:my-region:my-instance",
					"db2.example.com": "my-project:my-region:my-instance",
				},
			}),
			WithDNSResolver(),
			WithTokenSource(mock.EmptyTokenSource{}),
		},
	})

	testSuccessfulDial(
		context.Background(), t, d,
		"db.example.com",
	)
	testSuccessfulDial(
		context.Background(), t, d,
		"db2.example.com",
	)
}

func TestDialerSuccessfullyDialsDnsTxtRecordWithCustomARecords(t *testing.T) {
	inst := mock.NewFakeCSQLInstance(
		"my-project", "my-region", "my-instance",
		mock.WithDNSMapping("db.example.com", "INSTANCE", "CUSTOM_SAN"),
		mock.WithDNSMapping("db2.example.com", "INSTANCE", "CUSTOM_SAN"),
	)

	// This will create 2 separate connectionInfoCache entries, one for
	// each DNS name.
	d := setupDialer(t, setupConfig{
		testInstance: inst,
		reqs: []*mock.Request{
			mock.InstanceGetSuccess(inst, 2),
			mock.CreateEphemeralSuccess(inst, 2),
		},
		dialerOptions: []Option{
			withMockDNSResolver(&mockNetResolver{
				txtEntries: map[string]string{
					"db.example.com":  "my-project:my-region:my-instance",
					"db2.example.com": "my-project:my-region:my-instance",
				},
				hostEntries: map[string]string{
					"db.example.com":  "127.0.0.1",
					"db2.example.com": "127.0.0.2",
				},
			}),
			WithTokenSource(mock.EmptyTokenSource{}),
			WithDNSResolver(),
		},
	})

	testSuccessfulDial(
		context.Background(), t, d,
		"db.example.com",
	)
	testSuccessfulDial(
		context.Background(), t, d,
		"db2.example.com",
	)
}

func TestDialerFailsDnsTxtRecordWithInvalidCustomARecords(t *testing.T) {
	inst := mock.NewFakeCSQLInstance(
		"my-project", "my-region", "my-instance",
		mock.WithDNSMapping("db.example.com", "INSTANCE", "CUSTOM_SAN"),
	)

	// This will create 2 separate connectionInfoCache entries, one for
	// each DNS name.
	d := setupDialer(t, setupConfig{
		testInstance: inst,
		reqs: []*mock.Request{
			mock.InstanceGetSuccess(inst, 1),
			mock.CreateEphemeralSuccess(inst, 1),
		},
		dialerOptions: []Option{
			withMockDNSResolver(&mockNetResolver{
				txtEntries: map[string]string{
					"db.example.com": "my-project:my-region:my-instance",
				},
				hostEntries: map[string]string{
					"db.example.com": "1.1.1.1",
				},
			}),
			WithTokenSource(mock.EmptyTokenSource{}),
			WithDNSResolver(),
		},
	})
	ctx, cancelFn := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancelFn()
	_, err := d.Dial(ctx, "db.example.com")
	// Expect an error due to the timeout.
	if err == nil {
		t.Fatal("Dial should have failed due to bad IP address")
	}
	t.Log("timeout", err)

}

func TestDialerFailsDNSTxtRecordMissing(t *testing.T) {
	inst := mock.NewFakeCSQLInstance(
		"my-project", "my-region", "my-instance",
	)
	d := setupDialer(t, setupConfig{
		testInstance: inst,
		reqs:         []*mock.Request{},
		dialerOptions: []Option{
			withMockDNSResolver(&mockNetResolver{}),
			WithTokenSource(mock.EmptyTokenSource{}),
			WithDNSResolver(),
		},
	})
	_, err := d.Dial(context.Background(), "doesnt-exist.example.com")
	wantMsg := "no resolution for \"doesnt-exist.example.com\""
	if !strings.Contains(err.Error(), wantMsg) {
		t.Fatalf("want = %v, got = %v", wantMsg, err)
	}
}

type changingResolver struct {
	stage atomic.Int32
}

func (r *changingResolver) Resolve(ctx context.Context, name string) (instance.ConnName, error) {
	select {
	// for TestDialerClosesOldConnectionsOpenAfterDnsChange
	case <-ctx.Done():
		return instance.ConnName{}, fmt.Errorf("mock dns timeout error")
	default:
		// For TestDialerFailoverOnInstanceChange
		if name == "update.example.com" {
			if r.stage.Load() == 0 {
				return instance.ParseConnNameWithDomainName("my-project:my-region:my-instance", "update.example.com")
			}
			return instance.ParseConnNameWithDomainName("my-project:my-region:my-instance2", "update.example.com")
		}
		// TestDialerFailsDnsSrvRecordMissing
		return instance.ConnName{}, fmt.Errorf("no resolution for %q", name)
	}
}

func (r *changingResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

func TestDialerUpdatesAutomaticallyAfterDnsChange(t *testing.T) {
	// At first, the resolver will resolve
	// update.example.com to "my-instance"
	// Then, the resolver will resolve the same domain name to
	// "my-instance2".
	// This shows that on every call to Dial(), the dialer will resolve the
	// SRV record and connect to the correct instance.
	inst := mock.NewFakeCSQLInstance(
		"my-project", "my-region", "my-instance",
		mock.WithDNS("update.example.com"),
	)
	inst2 := mock.NewFakeCSQLInstance(
		"my-project", "my-region", "my-instance2",
		mock.WithDNS("update.example.com"),
	)
	r := &changingResolver{}

	d := setupDialer(t, setupConfig{
		skipServer: true,
		reqs: []*mock.Request{
			mock.InstanceGetSuccess(inst, 1),
			mock.CreateEphemeralSuccess(inst, 1),
			mock.InstanceGetSuccess(inst2, 1),
			mock.CreateEphemeralSuccess(inst2, 1),
		},
		dialerOptions: []Option{
			WithFailoverPeriod(10 * time.Millisecond),
			WithResolver(r),
			WithTokenSource(mock.EmptyTokenSource{}),
		},
	})

	// Execute the proxy for instance 1
	stop1 := mock.StartServerProxy(t, inst)
	t.Cleanup(func() {
		stop1()
	})

	testSuccessfulDial(
		context.Background(), t, d,
		"update.example.com",
	)
	stop1()
	r.stage.Store(1)

	time.Sleep(1 * time.Second)
	instCn, _ := instance.ParseConnNameWithDomainName("my-project:my-region:my-instance", "update.example.com")
	c, _ := d.cache[createKey(instCn)]
	if !c.isClosed() {
		t.Fatal("Expected monitoredCache to be closed after domain name changed. monitoredCache was not closed.")
	}

	// Execute the proxy for instance 2
	stop2 := mock.StartServerProxy(t, inst2)
	t.Cleanup(func() {
		stop2()
	})

	testSucessfulDialWithInstanceName(
		context.Background(), t, d,
		"update.example.com", "my-instance2",
	)

}

func TestDialerClosesOldConnectionsOpenAfterDnsChange(t *testing.T) {
	// At first, the resolver will resolve
	// update.example.com to "my-instance"
	// Then, the resolver will resolve the same domain name to
	// "my-instance2".
	// This shows that on every call to Dial(), the dialer will resolve the
	// SRV record and connect to the correct instance.
	inst := mock.NewFakeCSQLInstance(
		"my-project", "my-region", "my-instance",
		mock.WithDNS("update.example.com"),
	)
	inst2 := mock.NewFakeCSQLInstance(
		"my-project", "my-region", "my-instance2",
		mock.WithDNS("update.example.com"),
	)
	r := &changingResolver{}

	d := setupDialer(t, setupConfig{
		skipServer: true,
		reqs: []*mock.Request{
			mock.InstanceGetSuccess(inst, 1),
			mock.CreateEphemeralSuccess(inst, 1),
			mock.InstanceGetSuccess(inst2, 1),
			mock.CreateEphemeralSuccess(inst2, 1),
		},
		dialerOptions: []Option{
			WithFailoverPeriod(10 * time.Millisecond),
			WithResolver(r),
			WithTokenSource(mock.EmptyTokenSource{}),
			WithContextDebugLogger(&testLog{t: t}),
		},
	})

	srv := mock.NewFailoverTestServer(t)
	t.Cleanup(func() {
		srv.Close()
	})

	// Execute the mock server on 3307 for instance 1
	srv.Start(&inst)
	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	// Dial using a context with a timeout, similar to how the auth proxy
	// uses the dialer
	dialCtx, cancelFn := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFn()
	conn, err := d.Dial(dialCtx, "update.example.com")
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	c1 := mock.NewDbClient(t, conn, "c1")
	go c1.Execute(ctx)
	defer c1.Close()

	// Wait 15 seconds to give the fake client time to connect and
	// read from the socket
	time.Sleep(15 * time.Second)

	// Stop the instance1 mock, then start the instance2 mock server.
	// The dialer will need to refresh before it can connect to instance2.
	t.Logf("Switching to instance2 server")
	srv.Stop()
	srv.Start(&inst2)

	// Update the DNS resolver. This should signal to the dialer that
	// it should disconnect and refresh certificates.
	t.Logf("Updating DNS record")
	r.stage.Store(1)
	time.Sleep(1 * time.Second)

	// Dial the domain name again. This should now connect to instance2.
	dialCtx, cancelFn = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFn()
	conn, err = d.Dial(dialCtx, "update.example.com")
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	c2 := mock.NewDbClient(t, conn, "c2")
	go c2.Execute(ctx)
	defer c2.Close()

	// Wait for the dial context to expire. This ensures that the
	// DNS record loop in the dialer is not dependent on the dial context.
	time.Sleep(15 * time.Second)

	// Check that the client connections are in the correct state:
	// c1 should be closed because it connected before the domain name changed.
	// c2 should be open because it connected after the domain name changed.

	// Assert that c1 is closed because the dns record changed
	if !c1.Closed() {
		t.Errorf("want c1 closed, was open")
	}
	// Assert that c1 received some messages, only from inst1
	if len(c1.Recv()) == 0 {
		t.Errorf("c1 wants >0 messages received, got 0")
	}
	for _, m := range c1.Recv() {
		if m != "my-instance" {
			t.Errorf("c1 wants messages from my-instance, got %q", m)
		}
	}
	// Assert that c2 is open. No domain name changes have occurred.
	if c2.Closed() {
		t.Errorf("want c2 open, was closed")
	}
	// Assert that c2 received some messages, only from inst2
	if len(c2.Recv()) == 0 {
		t.Errorf("c2 wants >0 messages received, got 0")
	}
	for _, m := range c2.Recv() {
		if m != "my-instance2" {
			t.Errorf("c2 wants messages from my-instance2, got %q", m)
		}
	}
}

func TestDialerChecksSubjectAlternativeNameAndSucceeds(t *testing.T) {

	tcs := []struct {
		name   string
		legacy bool
		icn    string
		dn     string
	}{{
		name:   "domainName DnsName older",
		legacy: true,
		icn:    "my-project:my-region:my-instance",
	}, {
		name:   "domainName DnsNames newer",
		legacy: false,
		icn:    "my-project:my-region:my-instance",
	},
		{
			name:   "InstanceConnectionName DnsName older",
			legacy: true,
			icn:    "my-project:my-region:my-instance",
			dn:     "db.example.com",
		}, {
			name:   "InstanceConnectionName DnsNames newer",
			legacy: false,
			icn:    "my-project:my-region:my-instance",
			dn:     "db.example.com",
		}}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			// Create an instance with custom SAN 'db.example.com'
			var inst mock.FakeCSQLInstance
			if tc.legacy || tc.dn == "" {
				inst = mock.NewFakeCSQLInstance(
					"my-project", "my-region", "my-instance",
					mock.WithDNS("db.example.com"),
					mock.WithServerCAMode("GOOGLE_MANAGED_CAS_CA"),
				)
			} else {
				inst = mock.NewFakeCSQLInstance(
					"my-project", "my-region", "my-instance",
					mock.WithDNSMapping("db.example.com", "INSTANCE", "CUSTOM_SAN"),
					mock.WithServerCAMode("GOOGLE_MANAGED_CAS_CA"),
				)
			}

			d := setupDialer(t, setupConfig{
				testInstance: inst,
				reqs: []*mock.Request{
					mock.InstanceGetSuccess(inst, 1),
					mock.CreateEphemeralSuccess(inst, 1),
				},
				dialerOptions: []Option{
					withMockDNSResolver(&mockNetResolver{
						txtEntries: map[string]string{
							"db.example.com": "my-project:my-region:my-instance",
						},
					}),
					WithTokenSource(mock.EmptyTokenSource{}),
					WithDNSResolver(),
				},
			})
			dnOrIcn := tc.icn
			if tc.dn != "" {
				dnOrIcn = tc.dn
			}

			// Dial db.example.com
			testSuccessfulDial(
				context.Background(), t, d,
				dnOrIcn,
			)
		})
	}
}

func TestDialerChecksSubjectAlternativeNameAndFails(t *testing.T) {

	// Create an instance with custom SAN 'db.example.com'
	inst := mock.NewFakeCSQLInstance(
		"my-project", "my-region", "my-instance",
		mock.WithDNS("db.example.com"),
		mock.WithServerCAMode("GOOGLE_MANAGED_CAS_CA"),
	)

	// Resolve the dns name 'bad.example.com' to the the instance.
	d := setupDialer(t, setupConfig{
		testInstance: inst,
		reqs: []*mock.Request{
			mock.InstanceGetSuccess(inst, 1),
			mock.CreateEphemeralSuccess(inst, 1),
		},
		dialerOptions: []Option{
			withMockDNSResolver(&mockNetResolver{
				txtEntries: map[string]string{
					"bad.example.com": "my-project:my-region:my-instance",
				},
			}),
			WithTokenSource(mock.EmptyTokenSource{}),
			WithDNSResolver(),
		},
	})

	// Dial 'bad.example.com'. This will error as 'failed to verify certificate'
	_, err := d.Dial(
		context.Background(), "bad.example.com",
	)
	if err == nil {
		t.Fatal("want dial error, got no error")
	}
	if !strings.Contains(fmt.Sprint(err), "tls: failed to verify certificate") {
		t.Fatal("want error containing `tls: failed to verify certificate`. Got: ", err)
	}
}

func TestDialerChecksSubjectAlternativeNameAndFallsBackToCN(t *testing.T) {

	// Create an instance with custom SAN 'db.example.com'
	inst := mock.NewFakeCSQLInstance(
		"myProject", "myRegion", "myInstance",
		mock.WithDNS("db.example.com"),
		mock.WithMissingSAN("db.example.com"), // don't put db.example.com in the server cert.
	)

	// resolve db.example.com to the same instance
	d := setupDialer(t, setupConfig{
		testInstance: inst,
		reqs: []*mock.Request{
			mock.InstanceGetSuccess(inst, 2),
			mock.CreateEphemeralSuccess(inst, 2),
		},

		dialerOptions: []Option{
			withMockDNSResolver(&mockNetResolver{
				txtEntries: map[string]string{
					"db.example.com": "myProject:myRegion:myInstance",
				},
			}),
			WithTokenSource(mock.EmptyTokenSource{}),
			WithDNSResolver(),
		}})

	tcs := []struct {
		desc string
		icn  string
	}{
		{
			desc: "Fallback from connect with Instance Connection Name",
			icn:  "myProject:myRegion:myInstance",
		},
		{
			desc: "Fallback from connect with configured domain name",
			icn:  "db.example.com",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {

			// Dial 'db2.example.com'. This succeed overall.
			//  First the Hostname check will fail because the certificate does not
			//  contain db2.example.com
			//  Then the CN field check will succeed, because the instance connection
			//  name matches.
			conn, err := d.Dial(
				context.Background(), tc.icn,
			)
			if err != nil {
				t.Fatal("Want no error. Got: ", err)
			}
			_, err = conn.Write([]byte("hello world"))
			if err != nil {
				t.Fatal("Want no error. Got: ", err)
			}
		})
	}
}

func TestDialerRefreshesAfterRotateCACerts(t *testing.T) {
	tcs := []struct {
		desc            string
		rotateClientCA  bool
		wantErrorOnDial bool
		wantErrorOnRead bool
		useLazyRefresh  bool
	}{
		{
			desc:            "Rotating Client CA causes error on read, then refresh",
			rotateClientCA:  true,
			wantErrorOnRead: true,
		},
		{
			desc:            "Rotating all CAs causes error on dial, then refresh",
			wantErrorOnDial: true,
			wantErrorOnRead: false,
		},
		{
			desc:            "Rotating Client CA with lazy refresh causes error on read",
			rotateClientCA:  true,
			wantErrorOnRead: true,
			useLazyRefresh:  true,
		},
		{
			desc:            "Rotating all CAs with lazy refresh causes error on dial",
			wantErrorOnDial: true,
			useLazyRefresh:  true,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			inst := mock.NewFakeCSQLInstance(
				"my-project", "my-region", "my-instance",
				mock.WithDNS("db.example.com"),
				mock.WithServerCAMode("GOOGLE_MANAGED_CAS_CA"),
			)

			opts := []Option{
				WithTokenSource(mock.EmptyTokenSource{}),
				WithDebugLogger(&dialerTestLogger{t: t}),
			}
			if tc.useLazyRefresh {
				opts = append(opts, WithLazyRefresh())
			}

			d := setupDialer(t, setupConfig{
				skipServer:   true,
				testInstance: inst,
				reqs: []*mock.Request{
					mock.InstanceGetSuccess(inst, 2),
					mock.CreateEphemeralSuccess(inst, 2),
				},
				dialerOptions: opts,
			})
			cancel1 := mock.StartServerProxy(t, inst)
			t.Log("First attempt...")
			testSuccessfulDial(
				context.Background(), t, d,
				"my-project:my-region:my-instance",
			)
			t.Log("First attempt OK. Resetting client cert.")

			// Close the server
			cancel1()

			if tc.rotateClientCA {
				mock.RotateClientCA(inst)
			} else {
				mock.RotateCA(inst)
			}

			// Execute the server with new certificates
			cancel2 := mock.StartServerProxy(t, inst)
			defer cancel2()

			// Dial a second time.
			t.Log("Second attempt should fail...")
			conn, err := d.Dial(context.Background(), "my-project:my-region:my-instance")
			if err != nil {
				if tc.wantErrorOnDial {
					t.Logf("got error on dial as expected: %v", err)
				} else {
					t.Fatalf("want no dial error, got: %v", err)
				}
			} else if tc.wantErrorOnDial {
				t.Fatal("want dial error, got no error")
			}

			// If no error expected on dial, then attempt to read.
			if !tc.wantErrorOnDial {
				_, err = io.ReadAll(conn)
				if err != nil {
					if tc.wantErrorOnRead {
						t.Logf("got error on read as expected: %v", err)
					} else {
						t.Fatalf("want no read error, got: %v", err)
					}
				} else if tc.wantErrorOnRead {
					t.Fatal("want read error, got no error")
				}
			}
			t.Log("Second attempt done")

			// Dial again. This should complete after the refresh.
			t.Log("Third attempt...")
			testSuccessfulDial(
				context.Background(), t, d,
				"my-project:my-region:my-instance",
			)
			t.Log("Third attempt OK.")
		})
	}

}

type dialerTestLogger struct {
	t *testing.T
}

func (l *dialerTestLogger) Debugf(f string, args ...interface{}) {
	l.t.Logf(f, args...)
}

func TestNewMDXRequest(t *testing.T) {
	tcp := mdx.MetadataExchangeRequest_TCP
	uds := mdx.MetadataExchangeRequest_UDS
	tlsRes := mdx.MetadataExchangeRequest_TLS

	tcs := []struct {
		desc                     string
		ci                       cloudsql.ConnectionInfo
		cfg                      dialConfig
		metadataExchangeDisabled bool
		want                     *mdx.MetadataExchangeRequest
	}{
		{
			desc:                     "when metadata exchange is disabled",
			metadataExchangeDisabled: true,
			want:                     nil,
		},
		{
			desc: "when metadata exchange support is empty",
			ci: cloudsql.ConnectionInfo{
				MdxProtocolSupport: []string{},
			},
			cfg: dialConfig{
				mdxClientProtocolType: cloudsql.ClientProtocolTCP,
			},
			want: nil,
		},
		{
			desc: "when client protocol type is empty",
			ci: cloudsql.ConnectionInfo{
				MdxProtocolSupport: []string{"CLIENT_PROTOCOL_TYPE"},
			},
			cfg: dialConfig{
				mdxClientProtocolType: "",
			},
			want: nil,
		},
		{
			desc: "when client protocol type is not supported",
			ci: cloudsql.ConnectionInfo{
				MdxProtocolSupport: []string{"CLIENT_PROTOCOL_TYPE"},
			},
			cfg: dialConfig{
				mdxClientProtocolType: "unsupported",
			},
			want: nil,
		},
		{
			desc: "when client protocol type is not in metadata",
			ci: cloudsql.ConnectionInfo{
				MdxProtocolSupport: []string{"OTHER_FEATURE"},
			},
			cfg: dialConfig{
				mdxClientProtocolType: cloudsql.ClientProtocolTCP,
			},
			want: nil,
		},
		{
			desc: "when client protocol is CLIENT_PROTOCOL_TCP",
			ci: cloudsql.ConnectionInfo{
				MdxProtocolSupport: []string{"CLIENT_PROTOCOL_TYPE"},
			},
			cfg: dialConfig{
				mdxClientProtocolType: cloudsql.ClientProtocolTCP,
			},
			want: mdx.MetadataExchangeRequest_builder{ClientProtocolType: &tcp}.Build(),
		},
		{
			desc: "when client protocol is CLIENT_PROTOCOL_UDS",
			ci: cloudsql.ConnectionInfo{
				MdxProtocolSupport: []string{"CLIENT_PROTOCOL_TYPE"},
			},
			cfg: dialConfig{
				mdxClientProtocolType: cloudsql.ClientProtocolUDS,
			},
			want: mdx.MetadataExchangeRequest_builder{ClientProtocolType: &uds}.Build(),
		},
		{
			desc: "when client protocol is CLIENT_PROTOCOL_TLS",
			ci: cloudsql.ConnectionInfo{
				MdxProtocolSupport: []string{"CLIENT_PROTOCOL_TYPE"},
			},
			cfg: dialConfig{
				mdxClientProtocolType: cloudsql.ClientProtocolTLS,
			},
			want: mdx.MetadataExchangeRequest_builder{ClientProtocolType: &tlsRes}.Build(),
		},
	}

	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			got := newMDXRequest(tc.ci, tc.cfg, tc.metadataExchangeDisabled)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("want = %v, got = %v", tc.want, got)
			}
		})
	}
}

func TestDialerDnsResolutionFailureFallbackToPrivateIP(t *testing.T) {
	inst := mock.NewFakeCSQLInstance(
		"my-project", "my-region", "my-instance",
		mock.WithPrivateIP("127.0.0.2"),
		mock.WithDNS("db.example.com"),
	)
	d := setupDialer(t, setupConfig{
		testInstance: inst,
		reqs: []*mock.Request{
			mock.InstanceGetSuccess(inst, 1),
			mock.CreateEphemeralSuccess(inst, 1),
		},
		dialerOptions: []Option{
			withMockDNSResolver(&mockNetResolver{
				txtEntries: map[string]string{
					"db.example.com": "my-project:my-region:my-instance",
				},
				// hostEntries is EMPTY! So LookupHost("db.example.com") will FAIL!
			}),
			WithDNSResolver(),
			WithDefaultDialOptions(WithPrivateIP()), // Tell dialer to use Private IP type
			WithTokenSource(mock.EmptyTokenSource{}),
		},
	})

	// This should succeed because the dialer falls back to the private IP (10.0.0.1)
	// when DNS lookup fails!
	testSuccessfulDial(
		context.Background(), t, d,
		"db.example.com",
	)
}

func TestDialerPSCPSCFirst(t *testing.T) {
	dnsPSC := "abcde.12345.us-central1.sql-psc.goog"
	dnsReg := "abcde.12345.us-central1.sql.goog"

	inst := mock.NewFakeCSQLInstance(
		"my-project", "my-region", "my-instance",
		mock.WithPSC(true),
		mock.WithDNSMapping(dnsReg, "INSTANCE", "PRIVATE_SERVICE_CONNECT"),
		mock.WithDNSMapping(dnsPSC, "INSTANCE", "PRIVATE_SERVICE_CONNECT"),
	)

	var attempts []string
	dialFunc := func(_ context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		attempts = append(attempts, host)
		if host == dnsPSC {
			return nil, errors.New("PSC resolution/connection failed")
		}
		if host == dnsReg {
			return net.Dial(network, net.JoinHostPort("127.0.0.1", port))
		}
		return nil, fmt.Errorf("unexpected dial address: %s", addr)
	}

	d := setupDialer(t, setupConfig{
		testInstance: inst,
		reqs: []*mock.Request{
			mock.InstanceGetSuccess(inst, 1),
			mock.CreateEphemeralSuccess(inst, 1),
		},
		dialerOptions: []Option{
			WithTokenSource(mock.EmptyTokenSource{}),
			WithDialFunc(dialFunc),
		},
	})

	testSuccessfulDial(context.Background(), t, d, inst.String(), WithPSC())

	wantAttempts := []string{dnsPSC, dnsReg}
	if !reflect.DeepEqual(wantAttempts, attempts) {
		t.Fatalf("unexpected dial attempts, want = %v, got = %v", wantAttempts, attempts)
	}
}

func TestDialerPSCAllFailuresReturned(t *testing.T) {
	dnsPSC := "abcde.12345.us-central1.sql-psc.goog"
	dnsReg := "abcde.12345.us-central1.sql.goog"

	inst := mock.NewFakeCSQLInstance(
		"my-project", "my-region", "my-instance",
		mock.WithPSC(true),
		mock.WithDNSMapping(dnsReg, "INSTANCE", "PRIVATE_SERVICE_CONNECT"),
		mock.WithDNSMapping(dnsPSC, "INSTANCE", "PRIVATE_SERVICE_CONNECT"),
	)

	dialFunc := func(_ context.Context, _, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if host == dnsPSC {
			return nil, errors.New("PSC auto DNS failed")
		}
		if host == dnsReg {
			return nil, errors.New("manual DNS failed")
		}
		return nil, fmt.Errorf("unexpected dial address: %s", addr)
	}

	d := setupDialer(t, setupConfig{
		testInstance: inst,
		reqs: []*mock.Request{
			mock.InstanceGetSuccess(inst, 1),
			mock.CreateEphemeralSuccess(inst, 1),
		},
		dialerOptions: []Option{
			WithTokenSource(mock.EmptyTokenSource{}),
			WithDialFunc(dialFunc),
		},
	})

	_, err := d.Dial(context.Background(), inst.String(), WithPSC())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "PSC auto DNS failed") {
		t.Errorf("error %q does not contain error from first target", err.Error())
	}
	if !strings.Contains(err.Error(), "manual DNS failed") {
		t.Errorf("error %q does not contain error from second target", err.Error())
	}
}

type mockEmptyHostResolver struct {
	mockNetResolver
}

func (r *mockEmptyHostResolver) LookupHost(_ context.Context, _ string) ([]string, error) {
	return []string{}, nil
}

func TestDialerDnsResolutionEmptyFallbackToPrivateIP(t *testing.T) {
	inst := mock.NewFakeCSQLInstance(
		"my-project", "my-region", "my-instance",
		mock.WithPrivateIP("127.0.0.2"),
		mock.WithDNS("db.example.com"),
	)
	d := setupDialer(t, setupConfig{
		testInstance: inst,
		reqs: []*mock.Request{
			mock.InstanceGetSuccess(inst, 1),
			mock.CreateEphemeralSuccess(inst, 1),
		},
		dialerOptions: []Option{
			withMockDNSResolver(&mockEmptyHostResolver{
				mockNetResolver{
					txtEntries: map[string]string{
						"db.example.com": "my-project:my-region:my-instance",
					},
				},
			}),
			WithDNSResolver(),
			WithDefaultDialOptions(WithPrivateIP()),
			WithTokenSource(mock.EmptyTokenSource{}),
		},
	})

	testSuccessfulDial(
		context.Background(), t, d,
		"db.example.com",
	)
}

func TestBuiltInMetricsEnabledByDefault(t *testing.T) {
	// Restore the production default for this test only.
	builtInMetricsDefault = true
	t.Cleanup(func() { builtInMetricsDefault = false })

	ctx := context.Background()
	d, err := NewDialer(ctx, WithTokenSource(mock.EmptyTokenSource{}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	if !d.enableBuiltInMetrics {
		t.Fatal("built-in metrics should be enabled by default")
	}
}

func TestBuiltInMetricsExplicitlyDisabled(t *testing.T) {
	builtInMetricsDefault = true
	t.Cleanup(func() { builtInMetricsDefault = false })

	ctx := context.Background()
	d, err := NewDialer(ctx, WithTokenSource(mock.EmptyTokenSource{}), WithBuiltInMetrics(false))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()

	if d.enableBuiltInMetrics {
		t.Fatal("WithBuiltInMetrics(false) should disable built-in metrics")
	}
	if d.mClient != nil {
		t.Fatal("metric client should not be created when built-in metrics are disabled")
	}
	cn, err := instance.ParseConnName("my-project:my-region:my-instance")
	if err != nil {
		t.Fatal(err)
	}
	mr := d.metricRecorder(ctx, cn, tel.EnginePostgreSQL)
	if _, ok := mr.(tel.NullMetricRecorder); !ok {
		t.Fatalf("want tel.NullMetricRecorder when built-in metrics are disabled, got %T", mr)
	}
}

func TestBuiltInMetricsOptIn(t *testing.T) {
	ctx := context.Background()
	d, err := NewDialer(ctx,
		WithTokenSource(mock.EmptyTokenSource{}),
		WithBuiltInMetrics(true),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()

	if !d.enableBuiltInMetrics {
		t.Fatal("WithBuiltInMetrics should enable built-in metrics")
	}
	// The metric client depends on the environment's default credentials. If
	// they are unavailable (e.g., in CI), the client is nil and the recorder
	// must still degrade gracefully to a no-op.
	cn, err := instance.ParseConnName("my-project:my-region:my-instance")
	if err != nil {
		t.Fatal(err)
	}
	mr := d.metricRecorder(ctx, cn, tel.EnginePostgreSQL)
	_, isNull := mr.(tel.NullMetricRecorder)
	if d.mClient == nil && !isNull {
		t.Fatalf("want tel.NullMetricRecorder when the metric client is nil, got %T", mr)
	}
	if d.mClient != nil && isNull {
		t.Fatal("want a real metric recorder when built-in metrics are enabled and the metric client exists")
	}
}

func TestDialerPropagatesMetricResourceFields(t *testing.T) {
	ctx := context.Background()
	tcs := []struct {
		desc     string
		opts     []Option
		wantApp  string
		wantUA   string
		wantType string
	}{
		{
			desc:     "defaults",
			opts:     nil,
			wantApp:  "unknown",
			wantUA:   userAgent,
			wantType: tel.ConnectorTypeGo,
		},
		{
			desc: "application name and proxy user agent",
			opts: []Option{
				WithApplicationName("my-app"),
				WithUserAgent("cloud-sql-proxy/2.0.0"),
			},
			wantApp:  "my-app",
			wantUA:   userAgent + " cloud-sql-proxy/2.0.0",
			wantType: tel.ConnectorTypeAuthProxy,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			opts := append([]Option{WithTokenSource(mock.EmptyTokenSource{})}, tc.opts...)
			d, err := NewDialer(ctx, opts...)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = d.Close() }()
			if d.applicationName != tc.wantApp {
				t.Errorf("applicationName: got %q, want %q", d.applicationName, tc.wantApp)
			}
			if d.userAgent != tc.wantUA {
				t.Errorf("userAgent: got %q, want %q", d.userAgent, tc.wantUA)
			}
			if got := tel.ConnectorTypeValue(d.userAgent); got != tc.wantType {
				t.Errorf("connector type: got %q, want %q", got, tc.wantType)
			}
		})
	}
	if strings.ContainsAny(strings.TrimSpace(versionString), "\r\n") || strings.TrimSpace(versionString) == "" {
		t.Fatalf("versionString must be a non-empty single line, got %q", versionString)
	}
}

type sentinelTokenProvider struct{}

func (sentinelTokenProvider) Token(context.Context) (*auth.Token, error) {
	return &auth.Token{Value: "sentinel"}, nil
}

func TestMetricTokenProvider(t *testing.T) {
	saFile := filepath.Join(t.TempDir(), "sa.json")
	if err := os.WriteFile(saFile, fakeServiceAccount(""), 0o600); err != nil {
		t.Fatal(err)
	}
	apiTP := sentinelTokenProvider{}

	tcs := []struct {
		desc        string
		cfg         *dialerConfig
		env         map[string]string
		wantSameAPI bool
	}{
		{
			desc:        "caller-supplied token source is used as-is",
			cfg:         &dialerConfig{setCredentials: true},
			wantSameAPI: true,
		},
		{
			desc: "credentials JSON is re-scoped for monitoring",
			cfg: &dialerConfig{
				setCredentials:  true,
				credentialsJSON: fakeServiceAccount(""),
			},
			wantSameAPI: false,
		},
		{
			desc:        "application default credentials are re-scoped for monitoring",
			cfg:         &dialerConfig{setCredentials: false},
			env:         map[string]string{"GOOGLE_APPLICATION_CREDENTIALS": saFile},
			wantSameAPI: false,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			got, err := metricTokenProvider(tc.cfg, apiTP)
			if err != nil {
				t.Fatalf("metricTokenProvider: %v", err)
			}
			if got == nil {
				t.Fatal("metricTokenProvider returned nil token provider")
			}
			_, isSentinel := got.(sentinelTokenProvider)
			if isSentinel != tc.wantSameAPI {
				t.Fatalf("want same-as-API token provider = %v, got %v (%T)", tc.wantSameAPI, isSentinel, got)
			}
		})
	}
}

// fakeMetricServer is an in-memory Cloud Monitoring server that records
// CreateServiceTimeSeries requests.
type fakeMetricServer struct {
	monitoringpb.UnimplementedMetricServiceServer
	mu   sync.Mutex
	reqs []*monitoringpb.CreateTimeSeriesRequest
}

func (f *fakeMetricServer) CreateServiceTimeSeries(_ context.Context, req *monitoringpb.CreateTimeSeriesRequest) (*emptypb.Empty, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, req)
	return &emptypb.Empty{}, nil
}

func (f *fakeMetricServer) requests() []*monitoringpb.CreateTimeSeriesRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*monitoringpb.CreateTimeSeriesRequest(nil), f.reqs...)
}

func startFakeMetricServer(t *testing.T) (*fakeMetricServer, *grpc.ClientConn) {
	t.Helper()
	srv := grpc.NewServer()
	fake := &fakeMetricServer{}
	monitoringpb.RegisterMetricServiceServer(srv, fake)
	lis := bufconn.Listen(1024 * 1024)
	go func() { _ = srv.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		srv.Stop()
		_ = lis.Close()
	})
	return fake, conn
}

func TestBuiltInMetricsExportsThroughDialerClient(t *testing.T) {
	fake, conn := startFakeMetricServer(t)

	oldInterval := tel.DefaultExportInterval
	tel.DefaultExportInterval = 100 * time.Millisecond
	t.Cleanup(func() { tel.DefaultExportInterval = oldInterval })

	ctx := context.Background()
	d, err := NewDialer(ctx,
		WithTokenSource(mock.EmptyTokenSource{}),
		WithBuiltInMetrics(true),
		withMetricClientOptions(option.WithGRPCConn(conn)),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()

	if d.mClient == nil {
		t.Fatal("metric client should be created when built-in metrics are enabled")
	}
	cn, err := instance.ParseConnName("my-project:my-region:my-instance")
	if err != nil {
		t.Fatal(err)
	}
	mr := d.metricRecorder(ctx, cn, tel.EnginePostgreSQL)
	if _, isNull := mr.(tel.NullMetricRecorder); isNull {
		t.Fatal("want a real metric recorder when built-in metrics are enabled")
	}
	mr.RecordOpenConnectionCount(ctx, tel.Attributes{
		IPType:        "public",
		AttemptStatus: tel.ConnectSuccess,
	})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if reqs := fake.requests(); len(reqs) > 0 {
			if got, want := reqs[0].GetName(), "projects/my-project"; got != want {
				t.Fatalf("time series project: got %q, want %q", got, want)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("timed out waiting for the metric export to reach the in-memory server")
}

// resourceLabel returns the value of a monitored-resource label from the first
// time series in the first recorded request, or "" if absent.
func resourceLabel(reqs []*monitoringpb.CreateTimeSeriesRequest, key string) string {
	if len(reqs) == 0 || len(reqs[0].GetTimeSeries()) == 0 {
		return ""
	}
	return reqs[0].GetTimeSeries()[0].GetResource().GetLabels()[key]
}

func TestCloseFlushesBuiltInMetrics(t *testing.T) {
	fake, conn := startFakeMetricServer(t)

	// Make the periodic export effectively never run, so that any export we
	// observe must come from the flush in Close.
	oldInterval := tel.DefaultExportInterval
	tel.DefaultExportInterval = time.Hour
	t.Cleanup(func() { tel.DefaultExportInterval = oldInterval })

	ctx := context.Background()
	d, err := NewDialer(ctx,
		WithTokenSource(mock.EmptyTokenSource{}),
		WithBuiltInMetrics(true),
		withMetricClientOptions(option.WithGRPCConn(conn)),
	)
	if err != nil {
		t.Fatal(err)
	}
	cn, err := instance.ParseConnName("my-project:my-region:my-instance")
	if err != nil {
		t.Fatal(err)
	}
	mr := d.metricRecorder(ctx, cn, tel.EnginePostgreSQL)
	mr.RecordOpenConnectionCount(ctx, tel.Attributes{IPType: "public", AttemptStatus: tel.ConnectSuccess})

	if got := len(fake.requests()); got != 0 {
		t.Fatalf("expected no export before Close, got %d requests", got)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	reqs := fake.requests()
	if len(reqs) == 0 {
		t.Fatal("Close did not flush buffered built-in metrics")
	}
	if got, want := reqs[0].GetName(), "projects/my-project"; got != want {
		t.Fatalf("flushed time series project: got %q, want %q", got, want)
	}
	// Close must be idempotent and must not panic on already-shut-down
	// recorders.
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestMetricRecorderReplacementFlushesOldRecorder(t *testing.T) {
	fake, conn := startFakeMetricServer(t)

	oldInterval := tel.DefaultExportInterval
	tel.DefaultExportInterval = time.Hour
	t.Cleanup(func() { tel.DefaultExportInterval = oldInterval })

	ctx := context.Background()
	d, err := NewDialer(ctx,
		WithTokenSource(mock.EmptyTokenSource{}),
		WithBuiltInMetrics(true),
		withMetricClientOptions(option.WithGRPCConn(conn)),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	cn, err := instance.ParseConnName("my-project:my-region:my-instance")
	if err != nil {
		t.Fatal(err)
	}

	// Dial starts with an UNKNOWN-engine recorder and swaps to the real
	// engine once instance metadata is known. Metrics recorded on the first
	// recorder must not be lost when it is replaced.
	first := d.metricRecorder(ctx, cn, tel.UnknownValue)
	first.RecordOpenConnectionCount(ctx, tel.Attributes{IPType: "public", AttemptStatus: "connection_refused"})
	second := d.metricRecorder(ctx, cn, tel.EnginePostgreSQL)
	if first == second {
		t.Fatal("expected a new recorder once the database engine is known")
	}
	// The replaced recorder is flushed in the background, off the dial
	// path; wait for that flush rather than asserting it already happened.
	d.metricsWG.Wait()
	reqs := fake.requests()
	if len(reqs) == 0 {
		t.Fatal("replacing the recorder did not flush the old recorder's metrics")
	}
	if got, want := resourceLabel(reqs, "database_engine_type"), tel.UnknownValue; got != want {
		t.Fatalf("flushed resource database_engine_type: got %q, want %q", got, want)
	}
	// Recording on the replaced recorder must be safe (no panic) even though
	// its provider is shut down.
	first.RecordClosedConnectionCount(ctx, tel.Attributes{IPType: "public", DialStatus: tel.ConnectSuccess})

	// The replacement is the one that stays registered.
	if got := d.metricRecorder(ctx, cn, tel.EnginePostgreSQL); got != second {
		t.Fatal("expected the engine-specific recorder to remain registered")
	}

	// Shutting down the first recorder must not have closed the shared
	// metric client: the replacement recorder must still be able to export.
	second.RecordOpenConnectionCount(ctx, tel.Attributes{IPType: "public", AttemptStatus: tel.ConnectSuccess})
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	var sawEngine bool
	for _, r := range fake.requests() {
		if resourceLabel([]*monitoringpb.CreateTimeSeriesRequest{r}, "database_engine_type") == tel.EnginePostgreSQL {
			sawEngine = true
		}
	}
	if !sawEngine {
		t.Fatal("replacement recorder could not export after the old recorder was shut down (shared client closed?)")
	}
}

func TestCloseFlushesAllRecorders(t *testing.T) {
	fake, conn := startFakeMetricServer(t)

	oldInterval := tel.DefaultExportInterval
	tel.DefaultExportInterval = time.Hour
	t.Cleanup(func() { tel.DefaultExportInterval = oldInterval })

	ctx := context.Background()
	d, err := NewDialer(ctx,
		WithTokenSource(mock.EmptyTokenSource{}),
		WithBuiltInMetrics(true),
		withMetricClientOptions(option.WithGRPCConn(conn)),
	)
	if err != nil {
		t.Fatal(err)
	}
	// Two instances in different projects share one metric client. Closing
	// the Dialer must flush both, not just the first one shut down.
	for _, name := range []string{"proj-a:us-central1:inst-a", "proj-b:us-central1:inst-b"} {
		cn, err := instance.ParseConnName(name)
		if err != nil {
			t.Fatal(err)
		}
		mr := d.metricRecorder(ctx, cn, tel.EngineMySQL)
		mr.RecordOpenConnectionCount(ctx, tel.Attributes{IPType: "public", AttemptStatus: tel.ConnectSuccess})
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range fake.requests() {
		got[r.GetName()] = true
	}
	for _, want := range []string{"projects/proj-a", "projects/proj-b"} {
		if !got[want] {
			t.Errorf("Close did not flush metrics for %s; flushed projects: %v", want, got)
		}
	}
}

func TestWithComputePlatform(t *testing.T) {
	ctx := context.Background()

	t.Run("valid values are accepted and reported", func(t *testing.T) {
		for _, p := range []ComputePlatform{
			ComputePlatformGCE, ComputePlatformGKE, ComputePlatformCloudRun,
			ComputePlatformAppEngine, ComputePlatformCloudFunctions, ComputePlatformAIStudio,
		} {
			d, err := NewDialer(ctx, WithTokenSource(mock.EmptyTokenSource{}), WithComputePlatform(p))
			if err != nil {
				t.Fatalf("WithComputePlatform(%q): unexpected error: %v", p, err)
			}
			if d.computePlatform != string(p) {
				t.Errorf("WithComputePlatform(%q): dialer has %q", p, d.computePlatform)
			}
			_ = d.Close()
		}
	})

	t.Run("invalid values fail NewDialer", func(t *testing.T) {
		for _, p := range []ComputePlatform{
			"", "unknown", "AI_STUDIO", "ai-studio", "my-platform", "GCE",
		} {
			_, err := NewDialer(ctx, WithTokenSource(mock.EmptyTokenSource{}), WithComputePlatform(p))
			if err == nil {
				t.Errorf("WithComputePlatform(%q): want config error, got nil", p)
				continue
			}
			var cfgErr *errtype.ConfigError
			if !errors.As(err, &cfgErr) {
				t.Errorf("WithComputePlatform(%q): want *errtype.ConfigError, got %T: %v", p, err, err)
			}
		}
	})

	t.Run("default is auto-detected when metrics are enabled", func(t *testing.T) {
		t.Setenv("K_SERVICE", "svc")
		_, conn := startFakeMetricServer(t)
		d, err := NewDialer(ctx,
			WithTokenSource(mock.EmptyTokenSource{}),
			WithBuiltInMetrics(true),
			withMetricClientOptions(option.WithGRPCConn(conn)),
		)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = d.Close() }()
		if d.computePlatform != tel.PlatformCloudRun {
			t.Errorf("default computePlatform = %q, want %q", d.computePlatform, tel.PlatformCloudRun)
		}
	})

	t.Run("no environment detection when metrics are off", func(t *testing.T) {
		t.Setenv("K_SERVICE", "svc")
		d, err := NewDialer(ctx, WithTokenSource(mock.EmptyTokenSource{}), WithBuiltInMetrics(false))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = d.Close() }()
		if d.computePlatform != "" {
			t.Errorf("computePlatform = %q with metrics off, want no detection", d.computePlatform)
		}
		if d.clientRegion != tel.UnknownValue {
			t.Errorf("clientRegion = %q with metrics off, want %q", d.clientRegion, tel.UnknownValue)
		}
	})

	t.Run("override beats auto-detection and reaches the exported resource", func(t *testing.T) {
		t.Setenv("K_SERVICE", "svc") // would detect cloud_run
		fake, conn := startFakeMetricServer(t)
		oldInterval := tel.DefaultExportInterval
		tel.DefaultExportInterval = time.Hour
		t.Cleanup(func() { tel.DefaultExportInterval = oldInterval })

		d, err := NewDialer(ctx,
			WithTokenSource(mock.EmptyTokenSource{}),
			WithBuiltInMetrics(true),
			WithComputePlatform(ComputePlatformAIStudio),
			withMetricClientOptions(option.WithGRPCConn(conn)),
		)
		if err != nil {
			t.Fatal(err)
		}
		cn, err := instance.ParseConnName("my-project:my-region:my-instance")
		if err != nil {
			t.Fatal(err)
		}
		mr := d.metricRecorder(ctx, cn, tel.EnginePostgreSQL)
		mr.RecordOpenConnectionCount(ctx, tel.Attributes{IPType: "public", AttemptStatus: tel.ConnectSuccess})
		if err := d.Close(); err != nil {
			t.Fatal(err)
		}
		if got, want := resourceLabel(fake.requests(), "compute_platform"), tel.PlatformAIStudio; got != want {
			t.Fatalf("exported compute_platform = %q, want %q", got, want)
		}
	})
}

// TestAutoIPReportsResolvedIPType verifies that a dial requested with AutoIP
// reports the IP type actually used (here: the private IP, since the fake
// instance has no public IP) rather than the "auto" strategy.
func TestAutoIPReportsResolvedIPType(t *testing.T) {
	fake, conn := startFakeMetricServer(t)
	oldInterval := tel.DefaultExportInterval
	tel.DefaultExportInterval = time.Hour
	t.Cleanup(func() { tel.DefaultExportInterval = oldInterval })

	inst := mock.NewFakeCSQLInstance(
		"my-project", "my-region", "my-instance",
		mock.WithNoIPAddrs(),
		mock.WithPrivateIP("127.0.0.1"),
	)
	d := setupDialer(t, setupConfig{
		testInstance: inst,
		reqs: []*mock.Request{
			mock.InstanceGetSuccess(inst, 1),
			mock.CreateEphemeralSuccess(inst, 1),
		},
		dialerOptions: []Option{
			WithTokenSource(mock.EmptyTokenSource{}),
			WithBuiltInMetrics(true),
			withMetricClientOptions(option.WithGRPCConn(conn)),
			WithDefaultDialOptions(WithAutoIP()),
		},
	})
	testSuccessfulDial(context.Background(), t, d, "my-project:my-region:my-instance")
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	got := map[string]bool{}
	for _, r := range fake.requests() {
		for _, ts := range r.GetTimeSeries() {
			if v, ok := ts.GetMetric().GetLabels()["instance_ip_type"]; ok {
				got[v] = true
			}
		}
	}
	if !got[tel.IPTypePrivate] {
		t.Fatalf("want instance_ip_type=%q in exported series, got %v", tel.IPTypePrivate, got)
	}
	if got[tel.IPTypeAuto] {
		t.Fatalf("instance_ip_type must report the resolved type, but %q was exported: %v", tel.IPTypeAuto, got)
	}
}

func TestWithBuiltInMetricsFalseIsExplicitOptOut(t *testing.T) {
	ctx := context.Background()
	d, err := NewDialer(ctx, WithTokenSource(mock.EmptyTokenSource{}), WithBuiltInMetrics(false))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	if d.enableBuiltInMetrics || d.mClient != nil {
		t.Fatal("WithBuiltInMetrics(false) must leave built-in metrics disabled")
	}
	// Last option wins, as with every other Option.
	d2, err := NewDialer(ctx, WithTokenSource(mock.EmptyTokenSource{}), WithBuiltInMetrics(true), WithBuiltInMetrics(false))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d2.Close() }()
	if d2.enableBuiltInMetrics {
		t.Fatal("a later WithBuiltInMetrics(false) must override an earlier true")
	}
}

func TestDetectPrincipal(t *testing.T) {
	ctx := context.Background()
	saFile := filepath.Join(t.TempDir(), "sa.json")
	if err := os.WriteFile(saFile, fakeServiceAccount(""), 0o600); err != nil {
		t.Fatal(err)
	}
	tcs := []struct {
		desc string
		cfg  *dialerConfig
		env  map[string]string
		want string
	}{
		{
			desc: "credentials JSON exposes client_email",
			cfg:  &dialerConfig{setCredentials: true, credentialsJSON: fakeServiceAccount("")},
			want: "email@example.com",
		},
		{
			desc: "ADC via GOOGLE_APPLICATION_CREDENTIALS file",
			cfg:  &dialerConfig{},
			env:  map[string]string{"GOOGLE_APPLICATION_CREDENTIALS": saFile},
			want: "email@example.com",
		},
		{
			desc: "caller-supplied token source is opaque",
			cfg:  &dialerConfig{setCredentials: true},
			want: "",
		},
		{
			desc: "malformed credentials JSON yields empty, not an error",
			cfg:  &dialerConfig{setCredentials: true, credentialsJSON: []byte("not json")},
			want: "",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			if got := detectPrincipal(ctx, tc.cfg); got != tc.want {
				t.Errorf("detectPrincipal() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMetricsDisableHint(t *testing.T) {
	if got := metricsDisableHint(tel.ConnectorTypeGo); !strings.Contains(got, "WithBuiltInMetrics(false)") {
		t.Errorf("go hint = %q", got)
	}
	if got := metricsDisableHint(tel.ConnectorTypeAuthProxy); !strings.Contains(got, authProxyMetricsFlag+"=false") {
		t.Errorf("proxy hint = %q", got)
	}
}

func TestParseComputePlatform(t *testing.T) {
	tcs := []struct {
		in      string
		want    ComputePlatform
		wantErr bool
	}{
		{in: "gce", want: ComputePlatformGCE},
		{in: "gke", want: ComputePlatformGKE},
		{in: "cloud_run", want: ComputePlatformCloudRun},
		{in: "app_engine", want: ComputePlatformAppEngine},
		{in: "cloud_functions", want: ComputePlatformCloudFunctions},
		{in: "ai_studio", want: ComputePlatformAIStudio},
		{in: "AI_STUDIO", want: ComputePlatformAIStudio},
		{in: "  Cloud_Run\n", want: ComputePlatformCloudRun},
		{in: "", wantErr: true},
		{in: "unknown", wantErr: true},
		{in: "ai-studio", wantErr: true},
		{in: "aws", wantErr: true},
	}
	for _, tc := range tcs {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseComputePlatform(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseComputePlatform(%q) = %q, want error", tc.in, got)
				}
				// The error must tell the user what is valid.
				for _, p := range ComputePlatforms() {
					if !strings.Contains(err.Error(), string(p)) {
						t.Errorf("error %q does not list valid value %q", err, p)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseComputePlatform(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("ParseComputePlatform(%q) = %q, want %q", tc.in, got, tc.want)
			}
			// A parsed value is always accepted by WithComputePlatform.
			d, err := NewDialer(context.Background(), WithTokenSource(mock.EmptyTokenSource{}), WithComputePlatform(got))
			if err != nil {
				t.Fatalf("WithComputePlatform(ParseComputePlatform(%q)): %v", tc.in, err)
			}
			_ = d.Close()
		})
	}
}

// TestComputePlatformsMatchesInternalSet guards against drift between the
// public ComputePlatform list and the set internal/tel accepts as label
// values: adding a platform in one place but not the other fails here.
func TestComputePlatformsMatchesInternalSet(t *testing.T) {
	var public []string
	for _, p := range ComputePlatforms() {
		public = append(public, string(p))
	}
	internal := tel.ValidComputePlatformsForTest()
	slices.Sort(public)
	slices.Sort(internal)
	if !slices.Equal(public, internal) {
		t.Fatalf("public ComputePlatforms() %v != internal valid set %v", public, internal)
	}
	// The returned slice is a copy: mutating it must not affect the API.
	got := ComputePlatforms()
	got[0] = "tampered"
	if ComputePlatforms()[0] == "tampered" {
		t.Fatal("ComputePlatforms must return a copy")
	}
}
