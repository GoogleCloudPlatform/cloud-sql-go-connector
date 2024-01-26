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
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"testing"
	"time"

	"cloud.google.com/go/cloudsqlconn/errtype"
	"cloud.google.com/go/cloudsqlconn/instance"
)

func testInstanceConnName() instance.ConnName {
	cn, _ := instance.ParseConnName("my-project:my-region:my-instance")
	return cn
}

type stubRefresher struct {
	stubResult ConnectionInfo
	stubError  error
}

func (s stubRefresher) ConnectionInfo(
	context.Context, instance.ConnName, *rsa.PrivateKey, bool,
) (ConnectionInfo, error) {
	return s.stubResult, s.stubError
}

func TestInstanceEngineVersion(t *testing.T) {
	want := "SOME_DB_ENGINE_VERSION"
	r := stubRefresher{
		stubResult: ConnectionInfo{
			version: want,
		},
	}
	i := NewInstance(
		testInstanceConnName(), r, nil, 30*time.Second, false,
	)

	got, err := i.InstanceEngineVersion(context.Background())
	if err != nil {
		t.Fatalf("failed to retrieve engine version: %v", err)
	}
	if want != got {
		t.Errorf(
			"InstanceEngineVersion(%s) failed: want %v, got %v",
			want, got, err,
		)
	}
}

func TestConnectInfo(t *testing.T) {
	wantAddr := "0.0.0.0"
	wantServerName := "my-project:my-region:my-instance"

	r := stubRefresher{
		stubResult: ConnectionInfo{
			ipAddrs: map[string]string{PublicIP: wantAddr},
			conf: &tls.Config{
				ServerName: wantServerName,
			},
		},
	}
	i := NewInstance(testInstanceConnName(), r, nil, 30*time.Second, false)

	gotAddr, gotTLSCfg, err := i.ConnectInfo(context.Background(), PublicIP)
	if err != nil {
		t.Fatalf("failed to retrieve connect info: %v", err)
	}
	if gotAddr != wantAddr {
		t.Fatalf(
			"Unexpected IP address, want = %v, got = %v",
			wantAddr, gotAddr,
		)
	}
	if gotTLSCfg.ServerName != wantServerName {
		t.Fatalf(
			"Unexpected server name in TLS Config, want = %v, got = %v",
			wantServerName, gotTLSCfg.ServerName,
		)
	}
}

func TestConnectInfoAutoIP(t *testing.T) {
	tcs := []struct {
		desc   string
		ips    map[string]string
		wantIP string
	}{
		{
			desc: "when public IP is enabled",
			ips: map[string]string{
				PublicIP:  "8.8.8.8",
				PrivateIP: "10.0.0.1",
			},
			wantIP: "8.8.8.8",
		},
		{
			desc: "when only private IP is enabled",
			ips: map[string]string{
				PrivateIP: "10.0.0.1",
			},
			wantIP: "10.0.0.1",
		},
	}
	for _, tc := range tcs {
		r := stubRefresher{
			stubResult: ConnectionInfo{
				ipAddrs: tc.ips,
			},
		}
		i := NewInstance(testInstanceConnName(), r, nil, 30*time.Second, false)

		got, _, err := i.ConnectInfo(context.Background(), AutoIP)
		if err != nil {
			t.Fatalf("failed to retrieve connect info: %v", err)
		}

		if got != tc.wantIP {
			t.Fatalf(
				"Unexpected IP address, want = %v, got = %v",
				tc.wantIP, got,
			)
		}
	}
}

func TestConnectInfoErrors(t *testing.T) {
	r := stubRefresher{
		stubError: errors.New("refresh failed"),
		stubResult: ConnectionInfo{
			ipAddrs: map[string]string{
				PublicIP: "8.8.8.8", // no private IP
			},
		},
	}
	i := NewInstance(testInstanceConnName(), r, nil, 0, false)

	_, _, err := i.ConnectInfo(context.Background(), PublicIP)
	var wantErr *errtype.DialError
	if !errors.As(err, &wantErr) {
		t.Fatalf("want = %T, got = %v", wantErr, err)
	}

	// when client asks for wrong IP address type
	_, _, err = i.ConnectInfo(context.Background(), PrivateIP)
	if err == nil {
		t.Fatalf("ConnectInfo should fail with missing private IP")
	}
}

func TestClose(t *testing.T) {
	ctx := context.Background()

	r := stubRefresher{}
	i := NewInstance(testInstanceConnName(), r, nil, 30, false)
	_ = i.Close() // all future calls should fail

	_, _, err := i.ConnectInfo(ctx, PublicIP)
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
	// Set up an instance and then close it immediately
	r := stubRefresher{}
	i := NewInstance(testInstanceConnName(), r, nil, 30, false)
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
		t.Fatalf(
			"refresh did not return after a closed context."+
				" next pointer changed: want = %p, got = %p", next, i.next)
	}
}
