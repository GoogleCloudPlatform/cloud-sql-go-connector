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

// Package dialer contains methods and structs for creating secure, authorized connections to a Cloud SQL instance.
package dialer

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"sync"

	"github.com/kurtisvg/cloud-sql-go-connector/internal/cloudsql"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

var (
	once sync.Once
	d    *dialManager
)

// Dial returns a net.Conn connected to the specified Cloud SQL instance. The instance argument must be the
// instance's connection name, which is in the format "project-name:region:instance-name".
func Dial(ctx context.Context, instance string) (net.Conn, error) {
	return getDialer().dial(ctx, instance)
}

// defaultDialer provides the singleton dialer as a default for dial functinons.
func getDialer() *dialManager {
	once.Do(func() {
		// TODO: Provide functionality for customizing the dialer and getting errors returned.
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		client, err := sqladmin.NewService(context.Background())
		if err != nil {
			panic(err)
		}
		d = &dialManager{
			lock:      &sync.RWMutex{},
			instances: make(map[string]*cloudsql.Instance),
			sqladmin:  client,
			key:       key,
		}

	})
	return d
}

type dialManager struct {
	lock      *sync.RWMutex
	instances map[string]*cloudsql.Instance

	sqladmin *sqladmin.Service
	key      *rsa.PrivateKey
}

func (d *dialManager) instance(connName string) (i *cloudsql.Instance, err error) {
	// Check instance cache
	d.lock.RLock()
	i, ok := d.instances[connName]
	d.lock.RUnlock()
	if !ok {
		d.lock.Lock()
		// Recheck to ensure instance wasn't created between locks
		i, ok := d.instances[connName]
		if !ok {
			// Create a new instance
			i, err = cloudsql.NewInstance(connName, d.sqladmin, d.key)
			if err == nil { // if successful, store it in the map
				d.instances[connName] = i
			}
		}
		d.lock.Unlock()	
	}
	return i, err
}

func (d *dialManager) dial(ctx context.Context, instance string) (net.Conn, error) {
	i, err := d.instance(instance)
	if err != nil {
		return nil, err
	}
	return i.Connect(ctx)
}
