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

	"cloud.google.com/cloudsqlconn/internal/cloudsql"
	"golang.org/x/net/proxy"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

const (
	// defaultTCPKeepAlive is the default keep alive value used on connections to a Cloud SQL instance.
	defaultTCPKeepAlive = 30 * time.Second
)

// A Dialer is used to create connections to Cloud SQL instances.
type Dialer struct {
	lock      sync.RWMutex
	instances map[string]*cloudsql.Instance
	key       *rsa.PrivateKey

	sqladmin *sqladmin.Service

	defaultDialCfg dialCfg
}

// NewDialer creates a new Dialer.
func NewDialer(ctx context.Context, opts ...DialerOption) (*Dialer, error) {
	// TODO: Add shared / async key generation
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate rsa keys: %v", err)
	}

	cfg := &dialerConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	client, err := sqladmin.NewService(context.Background(), cfg.sqladminOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create sqladmin client: %v", err)
	}

	dialCfg := dialCfg{
		ipType:       cloudsql.IP_TYPE_PUBLIC,
		tcpKeepAlive: defaultTCPKeepAlive,
	}
	for _, opt := range cfg.dialOpts {
		opt(&dialCfg)
	}

	d := &Dialer{
		instances:      make(map[string]*cloudsql.Instance),
		sqladmin:       client,
		key:            key,
		defaultDialCfg: dialCfg,
	}
	return d, nil
}

// Dial creates an authorized connection to a Cloud SQL instance specified by it's instance connection name.
func (d *Dialer) Dial(ctx context.Context, instance string, opts ...DialOption) (net.Conn, error) {
	cfg := d.defaultDialCfg
	for _, opt := range opts {
		opt(&cfg)
	}

	i, err := d.instance(instance)
	if err != nil {
		return nil, err
	}
	ipAddrs, tlsCfg, err := i.ConnectInfo(ctx)
	if err != nil {
		return nil, err
	}
	addr, ok := ipAddrs[cfg.ipType]
	if !ok {
		return nil, fmt.Errorf("instance '%s' does not have IP of type '%s'", instance, cfg.ipType)
	}
	addr = net.JoinHostPort(addr, "3307")

	conn, err := proxy.Dial(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if c, ok := conn.(*net.TCPConn); ok {
		if err := c.SetKeepAlive(true); err != nil {
			return nil, fmt.Errorf("failed to set keep-alive: %w", err)
		}
		if err := c.SetKeepAlivePeriod(cfg.tcpKeepAlive); err != nil {
			return nil, fmt.Errorf("failed to set keep-alive period: %w", err)
		}
	}
	tlsConn := tls.Client(conn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("handshake failed: %w", err)
	}
	return tlsConn, err
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
			i, err = cloudsql.NewInstance(connName, d.sqladmin, d.key)
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
