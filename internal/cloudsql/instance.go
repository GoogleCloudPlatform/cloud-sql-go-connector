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
	"regexp"
	"sync"
	"time"

	"golang.org/x/time/rate"

	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

const (
	// refreshBuffer is the amount of time before a result expires to start a new refresh attempt.
	refreshBuffer = 5 * time.Minute
)

var (
	// Instance connection name is the format <PROJECT>:<REGION>:<INSTANCE>
	// Additionally, we have to support legacy "domain-scoped" projects (e.g. "google.com:PROJECT")
	connNameRegex = regexp.MustCompile("([^:]+(:[^:]+)?):([^:]+):([^:]+)")
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
	expiry time.Time
	err    error

	// timer that triggers refresh, can be used to cancel.
	timer *time.Timer
	// indicates the struct is ready to read from
	ready chan struct{}
}

// Cancel prevents the instanceInfo from starting, if it hasn't already started. Returns true if timer
// was stopped successfully, or false if it has already started.
func (r *refreshResult) Cancel() bool {
	return r.timer.Stop()
}

// Wait blocks until the refreshResult attempt is completed.
func (r *refreshResult) Wait(ctx context.Context) error {
	select {
	case <-r.ready:
		return r.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// IsValid returns true if this result is complete, successful, and is still valid.
func (r *refreshResult) IsValid() bool {
	// verify the result has finished running
	select {
	default:
		return false
	case <-r.ready:
		if r.err != nil || time.Now().After(r.expiry) {
			return false
		}
		return true
	}
}

// Instance manages the information used to connect to the Cloud SQL instance by periodically calling
// the Cloud SQL Admin API. It automatically refreshes the required information approximately 5 minutes
// before the previous certificate expires (every 55 minutes).
type Instance struct {
	connName

	clientLimiter  *rate.Limiter
	client         *sqladmin.Service
	key            *rsa.PrivateKey
	refreshTimeout time.Duration

	resultGuard sync.RWMutex
	// cur represents the current refreshResult that will be used to create connections. If a valid complete
	// refreshResult isn't available it's possible for cur to be equal to next.
	cur *refreshResult
	// next represents a future or ongoing refreshResult. Once complete, it will replace cur and schedule a
	// replacement to occur.
	next *refreshResult

	// TODO: add a way to close
}

// NewInstance initializes a new Instance given an instance connection name
func NewInstance(instance string, client *sqladmin.Service, key *rsa.PrivateKey, refreshTimeout time.Duration) (*Instance, error) {
	cn, err := parseConnName(instance)
	if err != nil {
		return nil, err
	}
	i := &Instance{
		connName:       cn,
		clientLimiter:  rate.NewLimiter(rate.Every(30*time.Second), 2),
		client:         client,
		key:            key,
		refreshTimeout: refreshTimeout,
	}
	// For the initial refresh operation, set cur = next so that connection requests block
	// until the first refresh is complete.
	i.resultGuard.Lock()
	i.cur = i.scheduleRefresh(0)
	i.next = i.cur
	i.resultGuard.Unlock()
	return i, nil
}

// ConnectInfo returns a map of IP types and a TLS config that can be used to connect to a Cloud SQL instance.
func (i *Instance) ConnectInfo(ctx context.Context) (map[string]string, *tls.Config, error) {
	i.resultGuard.RLock()
	res := i.cur
	i.resultGuard.RUnlock()
	err := res.Wait(ctx)
	if err != nil {
		return nil, nil, err
	}
	return res.md.ipAddrs, res.tlsCfg, nil
}

// ForceRefresh triggers an immediate refresh operation to be scheduled and used for future connection attempts.
func (i *Instance) ForceRefresh() {
	i.resultGuard.Lock()
	defer i.resultGuard.Unlock()
	// If the next refresh hasn't started yet, we can cancel it and start an immediate one
	if i.next.Cancel() {
		i.next = i.scheduleRefresh(0)
	}
	// block all sequential connection attempts on the next refresh result
	i.cur = i.next
}

// scheduleRefresh schedules a refresh operation to be triggered after a given duration. The returned refreshResult
// can be used to either Cancel or Wait for the operations result.
func (i *Instance) scheduleRefresh(d time.Duration) *refreshResult {
	res := &refreshResult{}
	res.ready = make(chan struct{})
	res.timer = time.AfterFunc(d, func() {
		ctx, cancel := context.WithTimeout(context.Background(), i.refreshTimeout)
		res.md, res.tlsCfg, res.expiry, res.err = performRefresh(ctx, i.client, i.clientLimiter, i.connName, i.key)
		cancel()

		close(res.ready)
		// Once the refresh is complete, update "current" with working result and schedule a new refresh
		i.resultGuard.Lock()
		defer i.resultGuard.Unlock()
		// if failed, scheduled the next refresh immediately
		if res.err != nil {
			i.next = i.scheduleRefresh(0)
			// keep using current info unless it's no longer valid
			// TODO: consider how to avoid supressing errors here
			if !i.cur.IsValid() {
				i.cur = res
			}
			return
		}
		// Update the current results, and schedule the next refresh in the future
		i.cur = res
		nextRefresh := i.cur.expiry.Add(-refreshBuffer)
		i.next = i.scheduleRefresh(time.Until(nextRefresh))
	})
	return res
}

// performRefresh immediately performs a full refresh operation using the Cloud SQL Admin API.
func performRefresh(ctx context.Context, client *sqladmin.Service, l *rate.Limiter, cn connName, k *rsa.PrivateKey) (metadata, *tls.Config, time.Time, error) {
	// avoid refreshing too often to try not to tax the SQL Admin API quotas
	err := l.Wait(ctx)
	if err != nil {
		return metadata{}, nil, time.Time{}, fmt.Errorf("refresh was throttled until context expired: %w", err)
	}

	// start async fetching the instance's metadata
	type mdRes struct {
		md  metadata
		err error
	}
	mdC := make(chan mdRes, 1)
	go func() {
		defer close(mdC)
		md, err := fetchMetadata(ctx, client, cn)
		mdC <- mdRes{md, err}
	}()

	// start async fetching the certs
	type ecRes struct {
		ec  tls.Certificate
		err error
	}
	ecC := make(chan ecRes, 1)
	go func() {
		defer close(ecC)
		ec, err := fetchEphemeralCert(ctx, client, cn, k)
		ecC <- ecRes{ec, err}
	}()

	// wait for the results of each operations
	var md metadata
	select {
	case r := <-mdC:
		if r.err != nil {
			return md, nil, time.Time{}, fmt.Errorf("fetch metadata failed: %w", r.err)
		}
		md = r.md
	case <-ctx.Done():
		return md, nil, time.Time{}, fmt.Errorf("refresh failed: %w", ctx.Err())
	}
	var ec tls.Certificate
	select {
	case r := <-ecC:
		if r.err != nil {
			return md, nil, time.Time{}, fmt.Errorf("fetch ephemeral cert failed: %w", r.err)
		}
		ec = r.ec
	case <-ctx.Done():
		return md, nil, time.Time{}, fmt.Errorf("refresh failed: %w", ctx.Err())
	}

	c := createTLSConfig(cn, md, ec)
	// This should never not be the case, but we check to avoid a potential nil-pointer
	expiry := time.Time{}
	if len(c.Certificates) > 0 {
		expiry = c.Certificates[0].Leaf.NotAfter
	}
	return md, c, expiry, nil
}
