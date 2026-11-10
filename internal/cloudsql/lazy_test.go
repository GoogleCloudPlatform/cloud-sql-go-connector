// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cloudsql

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/auth"
	"cloud.google.com/go/cloudsqlconn/instance"
	"cloud.google.com/go/cloudsqlconn/internal/mock"
	"github.com/jackc/pgx/v5/pgproto3"
)

func TestLazyRefreshCacheConnectionInfo(t *testing.T) {
	cn, _ := instance.ParseConnName("my-project:my-region:my-instance")
	inst := mock.NewFakeCSQLInstance(cn.Project(), cn.Region(), cn.Name())
	client, cleanup, err := mock.NewSQLAdminService(
		context.Background(),
		mock.InstanceGetSuccess(inst, 1),
		mock.CreateEphemeralSuccess(inst, 1),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			t.Fatalf("%v", err)
		}
	}()
	c := NewLazyRefreshCache(
		testInstanceConnName(), nullLogger{}, client,
		RSAKey, 30*time.Second, nil, "", false, nil,
	)

	ci, err := c.ConnectionInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ci.ConnectionName != cn {
		t.Fatalf("want = %v, got = %v", cn, ci.ConnectionName)
	}
	// Request connection info again to ensure it uses the cache and doesn't
	// send another API call.
	_, err = c.ConnectionInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
}

func TestLazyRefreshCacheForceRefresh(t *testing.T) {
	cn, _ := instance.ParseConnName("my-project:my-region:my-instance")
	inst := mock.NewFakeCSQLInstance(cn.Project(), cn.Region(), cn.Name())
	client, cleanup, err := mock.NewSQLAdminService(
		context.Background(),
		mock.InstanceGetSuccess(inst, 2),
		mock.CreateEphemeralSuccess(inst, 2),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			t.Fatalf("%v", err)
		}
	}()
	c := NewLazyRefreshCache(
		testInstanceConnName(), nullLogger{}, client,
		RSAKey, 30*time.Second, nil, "", false, nil,
	)

	_, err = c.ConnectionInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	c.ForceRefresh()

	_, err = c.ConnectionInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
}

// spyTokenProvider is a non-threadsafe spy for tracking token provider usage
type spyTokenProvider struct {
	mu    sync.Mutex
	count int
}

func (s *spyTokenProvider) Token(context.Context) (*auth.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count++
	return &auth.Token{}, nil
}

func (s *spyTokenProvider) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

func TestLazyRefreshCacheUpdateRefresh(t *testing.T) {
	cn, _ := instance.ParseConnName("my-project:my-region:my-instance")
	inst := mock.NewFakeCSQLInstance(cn.Project(), cn.Region(), cn.Name())
	client, cleanup, err := mock.NewSQLAdminService(
		context.Background(),
		mock.InstanceGetSuccess(inst, 2),
		mock.CreateEphemeralSuccess(inst, 2),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			t.Fatalf("%v", err)
		}
	}()

	spy := &spyTokenProvider{}
	c := NewLazyRefreshCache(
		testInstanceConnName(), nullLogger{}, client,
		RSAKey, 30*time.Second, spy, "", false, nil, // disable IAM AuthN at first
	)

	_, err = c.ConnectionInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if got := spy.callCount(); got != 0 {
		t.Fatal("auth.TokenProvider was called, but should not have been")
	}

	c.UpdateRefresh(ptr(true))

	_, err = c.ConnectionInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if got, want := spy.callCount(), 1; got != want {
		t.Fatalf(
			"auth.TokenProvider call count, got = %v, want = %v",
			got, want,
		)
	}
}

func TestLazyRefreshCache_ProbeConnection_PostgresStartupPacket(t *testing.T) {
	inst := mock.NewFakeCSQLInstance("my-project", "my-region", "my-instance", mock.WithEngineVersion("POSTGRES_15"))
	client, cleanup, err := mock.NewSQLAdminService(
		context.Background(),
		mock.InstanceGetSuccess(inst, 1),
		mock.CreateEphemeralSuccess(inst, 1),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{inst.Cert.Raw},
			PrivateKey:  inst.Key,
		}},
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	startupCh := make(chan *pgproto3.StartupMessage, 1)
	go func() {
		defer close(startupCh)
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		backend := pgproto3.NewBackend(conn, conn)
		msg, recvErr := backend.ReceiveStartupMessage()
		if recvErr != nil {
			return
		}
		if sm, ok := msg.(*pgproto3.StartupMessage); ok {
			startupCh <- sm
		}
		backend.Send(&pgproto3.AuthenticationOk{})
		_ = backend.Flush()
		_, _ = backend.Receive()
	}()

	customDial := func(ctx context.Context, ci ConnectionInfo) (net.Conn, error) {
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

	c := NewLazyRefreshCache(
		testInstanceConnName(), nullLogger{}, client,
		RSAKey, 30*time.Second, &spyTokenProvider{}, "", true,
		customDial,
	)
	c.RecordIAMPrincipal("iam-user@example.com", "mydb")

	if _, err := c.ConnectionInfo(context.Background()); err != nil {
		t.Fatalf("ConnectionInfo failed: %v", err)
	}

	select {
	case sm, ok := <-startupCh:
		if !ok {
			t.Fatal("startupCh closed without receiving PostgreSQL StartupMessage")
		}
		if got, want := sm.Parameters["user"], "iam-user@example.com"; got != want {
			t.Errorf("startup user = %q, want %q", got, want)
		}
		if got, want := sm.Parameters["database"], "mydb"; got != want {
			t.Errorf("startup database = %q, want %q", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for PostgreSQL StartupMessage from lazy refresh probe")
	}
}

func TestLazyRefreshCache_ProbeConnection_SkipsZeroPrincipalsAndNonPostgres(t *testing.T) {
	tcs := []struct {
		desc            string
		dbVersion       string
		recordPrincipal bool
	}{
		{
			desc:            "postgres with zero principals skips probe",
			dbVersion:       "POSTGRES_15",
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
			inst := mock.NewFakeCSQLInstance("my-project", "my-region", "my-instance", mock.WithEngineVersion(tc.dbVersion))
			client, cleanup, err := mock.NewSQLAdminService(
				context.Background(),
				mock.InstanceGetSuccess(inst, 1),
				mock.CreateEphemeralSuccess(inst, 1),
			)
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()

			dialCalls := 0
			customDial := func(context.Context, ConnectionInfo) (net.Conn, error) {
				dialCalls++
				t.Fatalf("unexpected probe dial for %s", tc.desc)
				return nil, nil
			}

			c := NewLazyRefreshCache(
				testInstanceConnName(), nullLogger{}, client,
				RSAKey, 30*time.Second, &spyTokenProvider{}, "", true,
				customDial,
			)
			if tc.recordPrincipal {
				c.RecordIAMPrincipal("iam-user@example.com", "mydb")
			}

			if _, err := c.ConnectionInfo(context.Background()); err != nil {
				t.Fatalf("ConnectionInfo failed: %v", err)
			}
			if dialCalls != 0 {
				t.Fatalf("dialCalls = %d, want 0", dialCalls)
			}
		})
	}
}

func ptr[T any](val T) *T {
	return &val
}

func TestLazyRefreshCacheForceRefreshIsRateLimited(t *testing.T) {
	cn, _ := instance.ParseConnName("my-project:my-region:my-instance")
	inst := mock.NewFakeCSQLInstance(cn.Project(), cn.Region(), cn.Name())
	// One initial refresh plus the burst of forced refreshes the limiter
	// allows; any further request is unexpected and fails the call.
	client, cleanup, err := mock.NewSQLAdminService(
		context.Background(),
		mock.InstanceGetSuccess(inst, 1+refreshBurst),
		mock.CreateEphemeralSuccess(inst, 1+refreshBurst),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			t.Fatal(err)
		}
	}()
	c := NewLazyRefreshCache(cn, nullLogger{}, client, RSAKey, 30*time.Second, nil, "", false, nil)
	if _, err := c.ConnectionInfo(context.Background()); err != nil {
		t.Fatal(err)
	}

	// A run of failed dials forces a refresh before each retry.
	for i := 0; i < 10; i++ {
		c.ForceRefresh()
		if _, err := c.ConnectionInfo(context.Background()); err != nil {
			t.Fatalf("ConnectionInfo() after forced refresh %d: %v", i+1, err)
		}
	}
}
