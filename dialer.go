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
	"fmt"
	"net"
	"sync"

	"cloud.google.com/cloudsqlconn/internal/cloudsql"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

type Dialer struct {
	lock      sync.RWMutex
	instances map[string]*cloudsql.Instance

	sqladmin *sqladmin.Service
	key      *rsa.PrivateKey
}

func NewDialer() (*Dialer, error) {
	// TODO: Add ability to customize keys / clients
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate rsa keys: %v", err)
	}
	client, err := sqladmin.NewService(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to create sqladmin client: %v", err)
	}
	d := &Dialer{
		instances: make(map[string]*cloudsql.Instance),
		sqladmin:  client,
		key:       key,
	}
	return d, nil
}

func (d *Dialer) Dial(ctx context.Context, instance string) (net.Conn, error) {
	i, err := d.instance(instance)
	if err != nil {
		return nil, err
	}
	return i.Connect(ctx)
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
