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
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/cloudsqlconn/errtype"
	"cloud.google.com/go/cloudsqlconn/internal/mock"
)

// genRSAKey generates an RSA key used for test.
func genRSAKey() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err) // unexpected, so just panic if it happens
	}
	return key
}

// RSAKey is used for test only.
var RSAKey = genRSAKey()

func TestParseConnName(t *testing.T) {
	tests := []struct {
		name string
		want connName
	}{
		{
			"project:region:instance",
			connName{"project", "region", "instance"},
		},
		{
			"google.com:project:region:instance",
			connName{"google.com:project", "region", "instance"},
		},
		{
			"project:instance", // missing region
			connName{},
		},
	}

	for _, tc := range tests {
		c, err := parseConnName(tc.name)
		if err != nil && tc.want != (connName{}) {
			t.Errorf("unexpected error: %e", err)
		}
		if c != tc.want {
			t.Errorf("ParseConnName(%s) failed: want %v, got %v", tc.name, tc.want, err)
		}
	}
}

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
		i, err := NewInstance("my-project:my-region:my-instance", client, RSAKey, 30*time.Second, nil, "", RefreshCfg{})
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

func TestConnectInfo(t *testing.T) {
	ctx := context.Background()
	wantAddr := "0.0.0.0"
	inst := mock.NewFakeCSQLInstance("my-project", "my-region", "my-instance", mock.WithPublicIP(wantAddr))
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

	i, err := NewInstance("my-project:my-region:my-instance", client, RSAKey, 30*time.Second, nil, "", RefreshCfg{})
	if err != nil {
		t.Fatalf("failed to create mock instance: %v", err)
	}

	gotAddr, gotTLSCfg, err := i.ConnectInfo(ctx, PublicIP)
	if err != nil {
		t.Fatalf("failed to retrieve connect info: %v", err)
	}

	if gotAddr != wantAddr {
		t.Fatalf(
			"ConnectInfo returned unexpected IP address, want = %v, got = %v",
			wantAddr, gotAddr,
		)
	}

	wantServerName := "my-project:my-region:my-instance"
	if gotTLSCfg.ServerName != wantServerName {
		t.Fatalf(
			"ConnectInfo return unexpected server name in TLS Config, want = %v, got = %v",
			wantServerName, gotTLSCfg.ServerName,
		)
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
		inst := mock.NewFakeCSQLInstance("p", "r", "i", opts...)
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

		i, err := NewInstance("p:r:i", client, RSAKey, 30*time.Second, nil, "", RefreshCfg{})
		if err != nil {
			t.Fatalf("failed to create mock instance: %v", err)
		}

		got, _, err := i.ConnectInfo(context.Background(), AutoIP)
		if err != nil {
			t.Fatalf("failed to retrieve connect info: %v", err)
		}

		if got != tc.wantIP {
			t.Fatalf(
				"ConnectInfo returned unexpected IP address, want = %v, got = %v",
				tc.wantIP, got,
			)
		}
	}
}

func TestConnectInfoErrors(t *testing.T) {
	ctx := context.Background()

	client, cleanup, err := mock.NewSQLAdminService(ctx)
	if err != nil {
		t.Fatalf("%s", err)
	}
	defer cleanup()

	// Use a timeout that should fail instantly
	im, err := NewInstance("my-project:my-region:my-instance", client, RSAKey, 0, nil, "", RefreshCfg{})
	if err != nil {
		t.Fatalf("failed to initialize Instance: %v", err)
	}

	_, _, err = im.ConnectInfo(ctx, PublicIP)
	var wantErr *errtype.DialError
	if !errors.As(err, &wantErr) {
		t.Fatalf("when connect info fails, want = %T, got = %v", wantErr, err)
	}

	// when client asks for wrong IP address type
	gotAddr, _, err := im.ConnectInfo(ctx, PrivateIP)
	if err == nil {
		t.Fatalf("expected ConnectInfo to fail but returned IP address = %v", gotAddr)
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
	im, err := NewInstance("my-proj:my-region:my-inst", client, RSAKey, 30, nil, "", RefreshCfg{})
	if err != nil {
		t.Fatalf("failed to initialize Instance: %v", err)
	}
	im.Close()

	_, _, err = im.ConnectInfo(ctx, PublicIP)
	if !strings.Contains(err.Error(), "context was canceled or expired") {
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
	i, err := NewInstance("my-proj:my-region:my-inst", client, RSAKey, 30, nil, "", RefreshCfg{})
	if err != nil {
		t.Fatalf("failed to initialize Instance: %v", err)
	}
	i.Close()

	// grab the current value of next before scheduling another refresh
	i.resultGuard.Lock()
	next := i.next
	i.resultGuard.Unlock()

	op := i.scheduleRefresh(time.Nanosecond)
	<-op.ready

	// if scheduleRefresh returns without scheduling another one,
	// i.next should be untouched and remain the same pointer value
	if i.next != next {
		t.Fatalf("refresh did not return after a closed context. next pointer changed: want = %p, got = %p", next, i.next)
	}
}
