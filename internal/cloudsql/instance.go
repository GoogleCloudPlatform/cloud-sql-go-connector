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
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"sync"
	"time"

	"golang.org/x/net/proxy"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

var (
	// Instance connection name is the format <PROJECT>:<REGION>:<INSTANCE>
	// Additionally, we have to support legacy "domain-scoped" projects (e.g. "google.com:PROJECT")
	connNameRegex = regexp.MustCompile("([^:]+(:[^:]+)?):([^:]+):([^:]+)")

	// defaultKeepAlive is the default keep alive value on connections created in this package.
	defaultKeepAlive = 30 * time.Second
)

// connName represents the "instance connection name", in the format "project:region:name". Use the
// "parseConnName" method to initialize this struct.
type connName struct {
	project string
	region  string
	name    string
}

func (c *connName) String() string {
	return fmt.Sprintf("%s:%s:%s", c.project, c.region, c.name)
}

// parseConnName initializes a new connName struct.
func parseConnName(cn string) (connName, error) {
	b := []byte(cn)
	m := connNameRegex.FindSubmatch(b)
	if m == nil {
		return connName{}, fmt.Errorf("invalid instance connection name - expected PROJECT:REGION:ID")
	}

	c := connName{
		project: string(m[1]),
		region:  string(m[3]),
		name:    string(m[4]),
	}
	return c, nil
}

// refreshResult is a pending result of a refresh operation of data used to connect securely. It should
// only be initialized by the Instance struct as part of a refresh cycle.
type refreshResult struct {
	md     metadata
	tlsCfg *tls.Config
	err    error

	// timer that triggers refresh, can be used to cancel.
	timer *time.Timer
	// indicates the struct is ready to read from
	ready chan struct{}
}

// Cancel prevents the instanceInfo from starting, if it hasn't already started. Returns true if timer
// was stopped successfully, or false if it has already started.
func (i *refreshResult) Cancel() bool {
	return i.timer.Stop()
}

// Wait blocks until the refreshResult attempt is completed.
func (i *refreshResult) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-i.ready:
		return i.err
	}
}

// Instance manages the information used to connect to the Cloud SQL instance by periodically calling
// the Cloud SQL Admin API. It automatically refreshes the required information approximately 5 minutes
// before the previous certificate expires (every 55 minutes).
type Instance struct {
	connName
	client *sqladmin.Service
	key    *rsa.PrivateKey

	resultGuard sync.RWMutex
	cur         *refreshResult
	next        *refreshResult

	// TODO: add a way to close
}

// NewInstance initializes a new Instance given an instance connection name
func NewInstance(instance string, client *sqladmin.Service, key *rsa.PrivateKey) (*Instance, error) {
	cn, err := parseConnName(instance)
	if err != nil {
		return nil, err
	}
	i := &Instance{
		connName: cn,
		client:   client,
		key:      key,
	}
	// For the initial refresh operation, set cur = next so that connection requests block
	// until the first refresh is complete.
	i.resultGuard.Lock()
	i.cur = i.scheduleRefresh(0)
	i.next = i.cur
	i.resultGuard.Unlock()
	return i, nil
}

// Connect returns a secure, authorized net.Conn to a Cloud SQL instance.
func (i *Instance) Connect(ctx context.Context) (net.Conn, error) {
	i.resultGuard.RLock()
	res := i.cur
	i.resultGuard.RUnlock()
	err := res.Wait(ctx)
	if err != nil {
		return nil, err
	}

	// TODO: Add better ipType support, including an opt to specify.
	addr := net.JoinHostPort(res.md.ipAddrs["PUBLIC"], "3307")
	conn, err := proxy.Dial(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if c, ok := conn.(*net.TCPConn); ok {
		if err := c.SetKeepAlive(true); err != nil {
			return nil, fmt.Errorf("failed to set keep-alive: %w", err)
		}
		if err := c.SetKeepAlivePeriod(defaultKeepAlive); err != nil {
			return nil, fmt.Errorf("failed to set keep-alive period: %w", err)
		}
	}

	tlsConn := tls.Client(conn, res.tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("handshake failed: %w", err)
	}
	return tlsConn, err
}

// scheduleRefresh schedules a refresh operation to be triggered after a given duration. The returned refreshResult
// can be used to either Cancel or Wait for the operations result.
func (i *Instance) scheduleRefresh(d time.Duration) *refreshResult {
	res := &refreshResult{}
	res.ready = make(chan struct{})
	res.timer = time.AfterFunc(d, func() {
		res.md, res.tlsCfg, res.err = performRefresh(i.client, i.connName, i.key, d)
		close(res.ready)
		// Once the refresh is complete, update "current" with working result and schedule a new refresh
		i.resultGuard.Lock()
		defer i.resultGuard.Unlock()
		// TODO: only replace cur result if it's not valid
		i.cur = res
		if res.err != nil {
			// TODO: add a backoff on retries
			// if failed, scheduled the next refresh immediately
			i.next = i.scheduleRefresh(0)
			return
		}
		i.next = i.scheduleRefresh(55 * time.Minute)
	})
	return res
}

// performRefresh immediately performs a full refresh operation using the Cloud SQL Admin API.
func performRefresh(client *sqladmin.Service, cn connName, k *rsa.PrivateKey, d time.Duration) (metadata, *tls.Config, error) {
	// TODO: consider adding an opt for configurable timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// TODO: perform these steps asynchronously and return the results
	md, err := fetchMetadata(ctx, client, cn)
	if err != nil {
		return md, nil, fmt.Errorf("fetch metadata failed: %w", err)
	}
	var ec tls.Certificate
	ec, err = fetchEphemeralCert(ctx, client, cn, k)
	if err != nil {
		return md, nil, fmt.Errorf("fetch ephemeral cert failed: %w", err)
	}
	return md, createTLSConfig(cn, md, ec), err
}
