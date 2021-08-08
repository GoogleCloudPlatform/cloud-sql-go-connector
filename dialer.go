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

package cloudsqlconn

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"cloud.google.com/go/cloudsqlconn/errtypes"
	"cloud.google.com/go/cloudsqlconn/internal/cloudsql"
	"cloud.google.com/go/cloudsqlconn/internal/trace"
	"golang.org/x/net/proxy"
	"google.golang.org/api/option"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

const (
	// versionString indicates the version of this library.
	versionString = "0.1.0-dev"
	userAgent     = "cloud-sql-go-connector/" + versionString

	// defaultTCPKeepAlive is the default keep alive value used on connections to a Cloud SQL instance.
	defaultTCPKeepAlive = 30 * time.Second
	// serverProxyPort is the port the server-side proxy receives connections on.
	serverProxyPort = "3307"
)

var (
	// defaultKey is the default RSA public/private keypair used by the clients.
	defaultKey    *rsa.PrivateKey
	defaultKeyErr error
	keyOnce       sync.Once
)

func getDefaultKeys() (*rsa.PrivateKey, error) {
	keyOnce.Do(func() {
		defaultKey, defaultKeyErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	return defaultKey, defaultKeyErr
}

// A Dialer is used to create connections to Cloud SQL instances.
//
// Use NewDialer to initialize a Dialer.
type Dialer struct {
	lock sync.RWMutex
	// instances map connection names (e.g., my-project:us-central1:my-instance)
	// to *cloudsql.Instance types.
	instances      map[string]*cloudsql.Instance
	key            *rsa.PrivateKey
	refreshTimeout time.Duration

	sqladmin *sqladmin.Service

	// defaultDialCfg holds the constructor level DialOptions, so that it can
	// be copied and mutated by the Dial function.
	defaultDialCfg dialCfg
}

// NewDialer creates a new Dialer.
//
// Initial calls to NewDialer make take longer than normal because generation of an
// RSA keypair is performed. Calls with a WithRSAKeyPair DialOption or after a default
// RSA keypair is generated will be faster.
func NewDialer(ctx context.Context, opts ...DialerOption) (*Dialer, error) {
	cfg := &dialerConfig{
		refreshTimeout: 30 * time.Second,
		sqladminOpts:   []option.ClientOption{option.WithUserAgent(userAgent)},
	}
	for _, opt := range opts {
		opt(cfg)
	}

	if cfg.rsaKey == nil {
		key, err := getDefaultKeys()
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA keys: %v", err)
		}
		cfg.rsaKey = key
	}

	client, err := sqladmin.NewService(ctx, cfg.sqladminOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create sqladmin client: %v", err)
	}

	dialCfg := dialCfg{
		ipType:       cloudsql.PublicIP,
		tcpKeepAlive: defaultTCPKeepAlive,
	}
	for _, opt := range cfg.dialOpts {
		opt(&dialCfg)
	}

	d := &Dialer{
		instances:      make(map[string]*cloudsql.Instance),
		key:            cfg.rsaKey,
		refreshTimeout: cfg.refreshTimeout,
		sqladmin:       client,
		defaultDialCfg: dialCfg,
	}
	return d, nil
}

// Dial returns a net.Conn connected to the specified Cloud SQL instance. The instance argument must be the
// instance's connection name, which is in the format "project-name:region:instance-name".
func (d *Dialer) Dial(ctx context.Context, instance string, opts ...DialOption) (conn net.Conn, err error) {
	var endDial trace.EndSpanFunc
	ctx, endDial = trace.StartSpan(ctx, "cloud.google.com/go/cloudsqlconn.Dial",
		trace.AddInstanceName(instance))
	defer func() { endDial(err) }()
	cfg := d.defaultDialCfg
	for _, opt := range opts {
		opt(&cfg)
	}

	var endInfo trace.EndSpanFunc
	ctx, endInfo = trace.StartSpan(ctx, "cloud.google.com/go/cloudsqlconn/internal.InstanceInfo")
	i, err := d.instance(instance)
	if err != nil {
		endInfo(err)
		return nil, err
	}
	addr, tlsCfg, err := i.ConnectInfo(ctx, cfg.ipType)
	if err != nil {
		endInfo(err)
		return nil, err
	}
	endInfo(err)

	var connectEnd trace.EndSpanFunc
	ctx, connectEnd = trace.StartSpan(ctx, "cloud.google.com/go/cloudsqlconn/internal.Connect")
	defer func() { connectEnd(err) }()
	addr = net.JoinHostPort(addr, serverProxyPort)
	conn, err = proxy.Dial(ctx, "tcp", addr)
	if err != nil {
		// refresh the instance info in case it caused the connection failure
		i.ForceRefresh()
		return nil, &errtypes.DialError{ConnName: i.String(),
			Message: "failed to dial", Err: err}
	}
	if c, ok := conn.(*net.TCPConn); ok {
		if err := c.SetKeepAlive(true); err != nil {
			return nil, &errtypes.DialError{
				ConnName: i.String(),
				Message:  "failed to set keep-alive",
				Err:      err,
			}
		}
		if err := c.SetKeepAlivePeriod(cfg.tcpKeepAlive); err != nil {
			return nil, &errtypes.DialError{
				ConnName: i.String(),
				Message:  "failed to set keep-alive period",
				Err:      err,
			}
		}
	}
	tlsConn := tls.Client(conn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		// refresh the instance info in case it caused the handshake failure
		i.ForceRefresh()
		_ = tlsConn.Close() // best effort close attempt
		return nil, &errtypes.DialError{
			ConnName: i.String(),
			Message:  "handshake failed",
			Err:      err,
		}
	}
	return tlsConn, nil
}

// Close closes the Dialer; it prevents the Dialer from refreshing the information
// needed to connect. Additional dial operations may succeed until the information
// expires.
func (d *Dialer) Close() {
	d.lock.Lock()
	defer d.lock.Unlock()
	for _, i := range d.instances {
		i.Close()
	}
}

func (d *Dialer) instance(connName string) (*cloudsql.Instance, error) {
	// Check instance cache
	d.lock.RLock()
	i, ok := d.instances[connName]
	d.lock.RUnlock()
	if !ok {
		d.lock.Lock()
		// Recheck to ensure instance wasn't created between locks
		i, ok = d.instances[connName]
		if !ok {
			// Create a new instance
			var err error
			i, err = cloudsql.NewInstance(connName, d.sqladmin, d.key, d.refreshTimeout)
			if err != nil {
				d.lock.Unlock()
				return nil, err
			}
			d.instances[connName] = i
		}
		d.lock.Unlock()
	}
	return i, nil
}
