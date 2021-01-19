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

package instance

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
)

// connName represents the "instance connection name", in the format "project:region:name"
type connName struct {
	project string
	region  string
	name    string
}

func (i *connName) String() string {
	return fmt.Sprintf("%s:%s:%s", i.project, i.region, i.name)
}

func parseConnName(cn string) (connName, error) {
	b := []byte(cn)
	m := connNameRegex.FindSubmatch(b)
	if m == nil {
		return connName{}, fmt.Errorf("invalid instance connection name - expected PROJECT:REGION:ID")
	}
	return connName{string(m[1]), string(m[3]), string(m[4])}, nil
}

// refreshResult represents information about the Cloud SQL instance needed to create connections.
type refreshResult struct {
	md     metadata
	tlsCfg *tls.Config
	err    error

	// timer that triggers refresh, can be used to cancel.
	timer *time.Timer
	// indicates the struct is ready to read from
	ready chan struct{}
}

// Cancel prevents the instanceInfo from starting, if it hasn't already started. Returns true if timer was stopped successfully, or false if it has already started.
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

// InstanceManager manages the information used to connect to the Cloud SQL instance by periodically calling
// the Cloud SQL Admin API. It automatically refreshes the required information every 55 minutes.
type instanceManager struct {
	connName
	client *sqladmin.Service
	key    *rsa.PrivateKey

	resultGuard *sync.RWMutex
	cur         *refreshResult
	next        *refreshResult

	// TODO: add a way to close
}

// NewInstanceManager initializes a new InstanceManager given an instance conneciton name
func NewInstanceManager(instanceConnName string, client *sqladmin.Service, key *rsa.PrivateKey) (*instanceManager, error) {
	cn, err := parseConnName(instanceConnName)
	if err != nil {
		return nil, err
	}
	i := &instanceManager{cn, client, key, &sync.RWMutex{}, nil, nil}
	// Kick off the inital refresh asynchronously
	i.resultGuard.Lock()
	i.cur = i.scheduleRefresh(0)
	i.next = i.cur
	i.resultGuard.Unlock()
	return i, nil
}

// Connect returns a connection to a Cloud SQL instance.
func (im *instanceManager) Connect(ctx context.Context) (net.Conn, error) {
	im.resultGuard.RLock()
	res := im.cur
	im.resultGuard.RUnlock()

	err := res.Wait(ctx)
	if err != nil {
		return nil, err
	}

	// TODO: add opt for selecting IP address type
	addr := net.JoinHostPort(res.md.ipAddrs["PUBLIC"], "3307")
	conn, err := proxy.Dial(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if c, ok := conn.(*net.TCPConn); ok {
		if err := c.SetKeepAlive(true); err != nil {
			return nil, fmt.Errorf("failed to set keep-alive: %w", err)
		}
		if err := c.SetKeepAlivePeriod(30 * time.Second); err != nil {
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

// scheduleRefresh schedules a refresh operation to be triggered after a given duration. The returned resultRefresh operation
// can be used to Cancel or Wait for the results of the operation.
func (im *instanceManager) scheduleRefresh(d time.Duration) *refreshResult {
	res := &refreshResult{}
	res.ready = make(chan struct{})
	res.timer = time.AfterFunc(d, func() {
		performRefresh(*im, res, d)
		// Once the refresh has been performed, replace "current" with the most recent result and schedule a new refresh
		im.resultGuard.Lock()
		if res.err == nil {
			im.cur = res
			im.next = im.scheduleRefresh(55 * time.Minute)
		} else {
			// If something went wrong, schedule the next refresh immediately instead
			// TODO: avoid replacing cur while it's still valid
			im.cur = res
			im.next = im.scheduleRefresh(0)
		}
		im.resultGuard.Unlock()
	})
	return res
}

// performRefresh immediately perfoms a full refresh operation using the Cloud SQL Admin API.
func performRefresh(im instanceManager, res *refreshResult, d time.Duration) {
	// TODO: consider adding an opt for configuratble timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	defer close(res.ready)

	// TODO: make this section async
	res.md, res.err = fetchMetadata(ctx, im.client, im.connName)
	if res.err != nil {
		return
	}
	var ec tls.Certificate
	ec, res.err = fetchEphemeralCert(ctx, im.client, im.connName, im.key)
	if res.err != nil {
		return
	}
	res.tlsCfg = createTLSConfig(im.connName, res.md, ec)
	return
}
