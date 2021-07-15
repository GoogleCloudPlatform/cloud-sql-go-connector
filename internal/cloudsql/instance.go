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

// ConnName represents the "instance connection name", in the format
// "project:region:name". Use the Use NewConnName to initialize this struct.
type ConnName struct {
	// Project is the project name that holds the database instance.
	Project string
	// Region is the GCP region where the database instance is deployed.
	Region string
	// Name is the database's instance name.
	Name string
}

func (c *ConnName) String() string {
	return fmt.Sprintf("%s:%s:%s", c.Project, c.Region, c.Name)
}

// NewConnName parses an instance connection name (project:region:name) into a
// ConnName.
func NewConnName(cn string) (ConnName, error) {
	b := []byte(cn)
	m := connNameRegex.FindSubmatch(b)
	if m == nil {
		return ConnName{}, fmt.Errorf("invalid instance connection name - expected PROJECT:REGION:ID")
	}

	c := ConnName{
		Project: string(m[1]),
		Region:  string(m[3]),
		Name:    string(m[4]),
	}
	return c, nil
}

// refreshResult is a pending result of a refresh operation of data used to connect securely. It should
// only be initialized by the Instance struct as part of a refresh cycle.
type refreshResult struct {
	md     Metadata
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
	ConnName
	key *rsa.PrivateKey
	r   Refresher

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
func NewInstance(cn ConnName, client *sqladmin.Service, key *rsa.PrivateKey, refreshTimeout time.Duration) *Instance {
	i := &Instance{
		ConnName: cn,
		key:      key,
		r: NewRefresher(
			refreshTimeout,
			30*time.Second,
			2,
			client,
		),
	}
	// For the initial refresh operation, set cur = next so that connection requests block
	// until the first refresh is complete.
	i.resultGuard.Lock()
	i.cur = i.scheduleRefresh(0)
	i.next = i.cur
	i.resultGuard.Unlock()
	return i
}

// ConnectInfo returns an IP address specified by ipType (i.e., public or
// private) and a TLS config that can be used to connect to a Cloud SQL
// instance.
func (i *Instance) ConnectInfo(ctx context.Context, ipType string) (string, *tls.Config, error) {
	i.resultGuard.RLock()
	res := i.cur
	i.resultGuard.RUnlock()
	err := res.Wait(ctx)
	if err != nil {
		return "", nil, err
	}
	addr, ok := res.md.IPAddrs[ipType]
	if !ok {
		return "", nil, fmt.Errorf("instance '%s' does not have IP of type '%s'", i, ipType)
	}
	return addr, res.tlsCfg, nil
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
		ctx := context.Background() // TODO: store this in Instance
		res.md, res.tlsCfg, res.expiry, res.err = i.r.PerformRefresh(ctx, i.ConnName, i.key)
		close(res.ready)

		// Once the refresh is complete, update "current" with working result and schedule a new refresh
		i.resultGuard.Lock()
		defer i.resultGuard.Unlock()
		// if failed, scheduled the next refresh immediately
		if res.err != nil {
			i.next = i.scheduleRefresh(0)
			// If the latest result is bad, avoid replacing the used result while it's
			// still valid and potentially able to provide successful connections.
			// TODO: This means that errors while the current result is still valid are
			// surpressed. We should try to surface errors in a more meaningful way.
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
