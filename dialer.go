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
	// serverProxyPort is the port the server-side proxy receives connections on.
	serverProxyPort = "3307"
)

var (
	// defaultKeys is the default pub/priv encryption keypair for the client, and is
	// shared between all Dialers that don't provide a different key
	defaultKeys    *rsa.PrivateKey
	defaultKeysErr error
	keysOnce       sync.Once
)

func getDefaultKeys() (*rsa.PrivateKey, error) {
	keysOnce.Do(func() {
		defaultKeys, defaultKeysErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	return defaultKeys, defaultKeysErr
}

// A Dialer is used to create connections to Cloud SQL instances.
//
// Dialer objects should only intialized using NewDialer.
type Dialer struct {
	lock      sync.RWMutex
	instances map[string]*cloudsql.Instance
	key       *rsa.PrivateKey

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
	cfg := &dialerConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	if cfg.rsaKey == nil {
		key, err := getDefaultKeys()
		if err != nil {
			return nil, fmt.Errorf("failed to generate rsa keys: %v", err)
		}
		cfg.rsaKey = key
	}

	client, err := sqladmin.NewService(context.Background(), cfg.sqladminOpts...)
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
		sqladmin:       client,
		key:            cfg.rsaKey,
		defaultDialCfg: dialCfg,
	}
	return d, nil
}

// Dial returns a net.Conn connected to the specified Cloud SQL instance. The instance argument must be the
// instance's connection name, which is in the format "project-name:region:instance-name".
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
	addr = net.JoinHostPort(addr, serverProxyPort)

	conn, err := proxy.Dial(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if c, ok := conn.(*net.TCPConn); ok {
		if err := c.SetKeepAlive(true); err != nil {
			return nil, fmt.Errorf("failed to set keep-alive: %v", err)
		}
		if err := c.SetKeepAlivePeriod(cfg.tcpKeepAlive); err != nil {
			return nil, fmt.Errorf("failed to set keep-alive period: %v", err)
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
