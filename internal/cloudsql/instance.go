// Copyright 2020 Google LLC
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
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"regexp"
	"sync"
	"time"

	"cloud.google.com/go/cloudsqlconn/errtype"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

const (
	// the refresh buffer is the amount of time before a refresh's result
	// expires that a new refresh operation begins.
	refreshBuffer = 4 * time.Minute

	// refreshInterval is the amount of time between refresh attempts as
	// enforced by the rate limiter.
	refreshInterval = 30 * time.Second

	// RefreshTimeout is the maximum amount of time to wait for a refresh
	// cycle to complete. This value should be greater than the
	// refreshInterval.
	RefreshTimeout = 60 * time.Second

	// refreshBurst is the initial burst allowed by the rate limiter.
	refreshBurst = 2
)

var (
	// Instance connection name is the format <PROJECT>:<REGION>:<INSTANCE>
	// Additionally, we have to support legacy "domain-scoped" projects
	// (e.g. "google.com:PROJECT")
	connNameRegex = regexp.MustCompile("([^:]+(:[^:]+)?):([^:]+):([^:]+)")
)

// connName represents the "instance connection name", in the format
// "project:region:name".
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
		err := errtype.NewConfigError(
			"invalid instance connection name, expected PROJECT:REGION:INSTANCE",
			cn,
		)
		return connName{}, err
	}

	c := connName{
		project: string(m[1]),
		region:  string(m[3]),
		name:    string(m[4]),
	}
	return c, nil
}

// refreshOperation is a pending result of a refresh operation of data used to
// connect securely. It should only be initialized by the Instance struct as
// part of a refresh cycle.
type refreshOperation struct {
	// indicates the struct is ready to read from
	ready chan struct{}
	// timer that triggers refresh, can be used to cancel.
	timer  *time.Timer
	err    error
	expiry time.Time
	tlsCfg *tls.Config
	md     metadata
}

// cancel prevents the instanceInfo from starting, if it hasn't already
// started. Returns true if timer was stopped successfully, or false if it has
// already started.
func (r *refreshOperation) cancel() bool {
	return r.timer.Stop()
}

// isValid returns true if this result is complete, successful, and is still
// valid.
func (r *refreshOperation) isValid() bool {
	// verify the result has finished running
	select {
	default:
		return false
	case <-r.ready:
		if r.err != nil || time.Now().After(r.expiry.Round(0)) {
			return false
		}
		return true
	}
}

// RefreshCfg is a of attributes that trigger new refresh operations.
type RefreshCfg struct {
	UseIAMAuthN bool
}

// Instance manages the information used to connect to the Cloud SQL instance
// by periodically calling the Cloud SQL Admin API. It automatically refreshes
// the required information approximately 4 minutes before the previous
// certificate expires (every ~56 minutes).
type Instance struct {
	// OpenConns is the number of open connections to the instance.
	OpenConns uint64

	connName
	key *rsa.PrivateKey

	// refreshTimeout sets the maximum duration a refresh cycle can run
	// for.
	refreshTimeout time.Duration
	// l controls the rate at which refresh cycles are run.
	l *rate.Limiter
	r refresher

	resultGuard sync.RWMutex
	RefreshCfg  RefreshCfg
	// cur represents the current refreshOperation that will be used to
	// create connections. If a valid complete refreshOperation isn't
	// available it's possible for cur to be equal to next.
	cur *refreshOperation
	// next represents a future or ongoing refreshOperation. Once complete,
	// it will replace cur and schedule a replacement to occur.
	next *refreshOperation

	// ctx is the default ctx for refresh operations. Canceling it prevents
	// new refresh operations from being triggered.
	ctx    context.Context
	cancel context.CancelFunc
}

// NewInstance initializes a new Instance given an instance connection name
func NewInstance(
	instance string,
	client *sqladmin.Service,
	key *rsa.PrivateKey,
	refreshTimeout time.Duration,
	ts oauth2.TokenSource,
	dialerID string,
	r RefreshCfg,
) (*Instance, error) {
	cn, err := parseConnName(instance)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	i := &Instance{
		connName: cn,
		key:      key,
		l:        rate.NewLimiter(rate.Every(refreshInterval), refreshBurst),
		r: newRefresher(
			client,
			ts,
			dialerID,
		),
		refreshTimeout: refreshTimeout,
		RefreshCfg:     r,
		ctx:            ctx,
		cancel:         cancel,
	}
	// For the initial refresh operation, set cur = next so that connection
	// requests block until the first refresh is complete.
	i.resultGuard.Lock()
	i.cur = i.scheduleRefresh(0)
	i.next = i.cur
	i.resultGuard.Unlock()
	return i, nil
}

// Close closes the instance; it stops the refresh cycle and prevents it from
// making additional calls to the Cloud SQL Admin API.
func (i *Instance) Close() {
	i.cancel()
}

// ConnectInfo returns an IP address specified by ipType (i.e., public or
// private) and a TLS config that can be used to connect to a Cloud SQL
// instance.
func (i *Instance) ConnectInfo(ctx context.Context, ipType string) (string, *tls.Config, error) {
	res, err := i.result(ctx)
	if err != nil {
		return "", nil, err
	}
	var (
		addr string
		ok   bool
	)
	switch ipType {
	case AutoIP:
		// Try Public first
		addr, ok = res.md.ipAddrs[PublicIP]
		if !ok {
			// Try Private second
			addr, ok = res.md.ipAddrs[PrivateIP]
		}
	default:
		addr, ok = res.md.ipAddrs[ipType]
	}
	if !ok {
		err := errtype.NewConfigError(
			fmt.Sprintf("instance does not have IP of type %q", ipType),
			i.String(),
		)
		return "", nil, err
	}
	return addr, res.tlsCfg, nil
}

// InstanceEngineVersion returns the engine type and version for the instance.
// The value coresponds to one of the following types for the instance:
// https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/SqlDatabaseVersion
func (i *Instance) InstanceEngineVersion(ctx context.Context) (string, error) {
	res, err := i.result(ctx)
	if err != nil {
		return "", err
	}
	return res.md.version, nil
}

// UpdateRefresh cancels all existing refresh attempts and schedules new
// attempts with the provided config.
func (i *Instance) UpdateRefresh(cfg RefreshCfg) {
	i.resultGuard.Lock()
	defer i.resultGuard.Unlock()
	// Cancel any pending refreshes
	i.cur.cancel()
	i.next.cancel()
	// update the refreshcfg as needed
	i.RefreshCfg = cfg
	// reschedule a new refresh immiediately
	i.cur = i.scheduleRefresh(0)
	i.next = i.cur
}

// ForceRefresh triggers an immediate refresh operation to be scheduled and
// used for future connection attempts.
func (i *Instance) ForceRefresh() {
	i.resultGuard.Lock()
	defer i.resultGuard.Unlock()
	// If the next refresh hasn't started yet, we can cancel it and start
	// an immediate one
	if i.next.cancel() {
		i.next = i.scheduleRefresh(0)
	}
	// block all sequential connection attempts on the next refresh result
	i.cur = i.next
}

// result returns the most recent refresh result (waiting for it to complete if
// necessary)
func (i *Instance) result(ctx context.Context) (*refreshOperation, error) {
	i.resultGuard.RLock()
	res := i.cur
	i.resultGuard.RUnlock()
	var err error
	select {
	case <-res.ready:
		err = res.err
	case <-ctx.Done():
		err = ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	return res, nil
}

// refreshDuration returns the duration to wait before starting the next
// refresh. Usually that duration will be half of the time until certificate
// expiration.
func refreshDuration(now, certExpiry time.Time) time.Duration {
	d := certExpiry.Sub(now.Round(0))
	if d < time.Hour {
		// Something is wrong with the certificate, refresh now.
		if d < refreshBuffer {
			return 0
		}
		// Otherwise wait until 4 minutes before expiration for next
		// refresh cycle.
		return d - refreshBuffer
	}
	return d / 2
}

// scheduleRefresh schedules a refresh operation to be triggered after a given
// duration. The returned refreshOperation can be used to either Cancel or Wait
// for the operation's result.
func (i *Instance) scheduleRefresh(d time.Duration) *refreshOperation {
	r := &refreshOperation{}
	r.ready = make(chan struct{})
	r.timer = time.AfterFunc(d, func() {
		ctx, cancel := context.WithTimeout(i.ctx, i.refreshTimeout)
		defer cancel()

		// avoid refreshing too often to try not to tax the SQL Admin
		// API quotas
		err := i.l.Wait(ctx)
		if err != nil {
			r.err = errtype.NewDialError(
				"context was canceled or expired before refresh completed",
				i.connName.String(),
				nil,
			)
		} else {
			r.md, r.tlsCfg, r.expiry, r.err = i.r.performRefresh(
				ctx, i.connName, i.key, i.RefreshCfg.UseIAMAuthN)
		}

		close(r.ready)

		select {
		case <-i.ctx.Done():
			// instance has been closed, don't schedule anything
			return
		default:
		}

		// Once the refresh is complete, update "current" with working
		// result and schedule a new refresh
		i.resultGuard.Lock()
		defer i.resultGuard.Unlock()

		// if failed, scheduled the next refresh immediately
		if r.err != nil {
			i.next = i.scheduleRefresh(0)
			// If the latest result is bad, avoid replacing the
			// used result while it's still valid and potentially
			// able to provide successful connections. TODO: This
			// means that errors while the current result is still
			// valid are surpressed. We should try to surface
			// errors in a more meaningful way.
			if !i.cur.isValid() {
				i.cur = r
			}
			return
		}

		// Update the current results, and schedule the next refresh in
		// the future
		i.cur = r
		t := refreshDuration(time.Now(), i.cur.expiry)
		i.next = i.scheduleRefresh(t)
	})
	return r
}

// String returns the instance's connection name.
func (i *Instance) String() string {
	return i.connName.String()
}
