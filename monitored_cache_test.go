// Copyright 2024 Google LLC
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
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"cloud.google.com/go/cloudsqlconn/instance"
	"cloud.google.com/go/cloudsqlconn/internal/cloudsql"
)

type testLog struct {
	t *testing.T
}

func (l *testLog) Debugf(_ context.Context, f string, args ...interface{}) {
	l.t.Logf(f, args...)
}

func TestMonitoredCache_purgeClosedConns(t *testing.T) {
	cn, _ := instance.ParseConnNameWithDomainName("my-project:my-region:my-instance", "db.example.com")
	r := cloudsql.NewDNSResolver(&mockNetResolver{txtEntries: map[string]string{"db.example.com": "my-project:my-region:my-instance"}})
	c := newMonitoredCache(&spyConnectionInfoCache{}, cn, 10*time.Millisecond, r, &testLog{t: t})

	// Add connections
	c.mu.Lock()
	c.openConns = []*instrumentedConn{
		&instrumentedConn{closed: false},
		&instrumentedConn{closed: true},
	}
	c.mu.Unlock()

	// wait for the resolver to run
	time.Sleep(100 * time.Millisecond)
	c.mu.Lock()
	if got := len(c.openConns); got != 1 {
		t.Fatalf("got %d, want 1. Expected openConns to only contain open connections", got)
	}
	c.mu.Unlock()

}

func TestMonitoredCache_checkDomainName_instanceChanged(t *testing.T) {
	cn, _ := instance.ParseConnNameWithDomainName("my-project:my-region:my-instance", "update.example.com")
	r := &changingResolver{}
	c := newMonitoredCache(&spyConnectionInfoCache{}, cn, 10*time.Millisecond, r, &testLog{t: t})

	// Dont' change the instance yet. Check that the connection is open.
	// wait for the resolver to run
	time.Sleep(100 * time.Millisecond)
	if c.isClosed() {
		t.Fatal("got cache closed, want cache open")
	}
	// update the domain name
	r.stage.Store(1)

	// wait for the resolver to run
	time.Sleep(100 * time.Millisecond)
	if !c.isClosed() {
		t.Fatal("got cache open, want cache closed")
	}

}

func TestMonitoredCache_Close(t *testing.T) {
	cn, _ := instance.ParseConnNameWithDomainName("my-project:my-region:my-instance", "update.example.com")
	var closeFuncCalls atomic.Int32

	r := &changingResolver{}

	c := newMonitoredCache(&spyConnectionInfoCache{}, cn, 10*time.Millisecond, r, &testLog{t: t})
	inc := func() {
		closeFuncCalls.Add(1)
	}

	c.mu.Lock()
	// set up the state as if there were 2 open connections.
	c.openConns = []*instrumentedConn{
		{
			closed:       false,
			closeFunc:    inc,
			stopReporter: func() {},
			Conn:         &mockConn{},
		},
		{
			closed:       false,
			closeFunc:    inc,
			stopReporter: func() {},
			Conn:         &mockConn{},
		},
		{
			closed:       true,
			closeFunc:    inc,
			stopReporter: func() {},
			Conn:         &mockConn{},
		},
	}
	c.openConnsCount.Store(2)
	c.mu.Unlock()

	c.Close()
	if !c.isClosed() {
		t.Fatal("got cache open, want cache closed")
	}
	// wait for closeFunc() to be called.
	time.Sleep(100 * time.Millisecond)
	if got := closeFuncCalls.Load(); got != 2 {
		t.Fatalf("got %d, want 2", got)
	}

}

type mockConn struct {
}

func (m *mockConn) Read(_ []byte) (int, error) {
	return 0, nil
}

func (m *mockConn) Write(_ []byte) (int, error) {
	return 0, nil
}

func (m *mockConn) Close() error {
	return nil
}

func (m *mockConn) LocalAddr() net.Addr {
	return net.TCPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:3307"))
}

func (m *mockConn) RemoteAddr() net.Addr {
	return net.TCPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:3307"))
}

func (m *mockConn) SetDeadline(_ time.Time) error {
	return nil
}

func (m *mockConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (m *mockConn) SetWriteDeadline(_ time.Time) error {
	return nil
}
