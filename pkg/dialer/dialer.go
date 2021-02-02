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

package dialer

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"sync"

	"github.com/kurtisvg/cloud-sql-connector-go/pkg/dialer/internal/instance"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

var (
	once sync.Once
	d    *dialManager
)

// Dial returns a net.Conn connected to the Cloud SQL instance specified. The instance argument must be the
// instance's connection name, which is in the format "project-name:region:instance-name".
func Dial(ctx context.Context, instance string) (net.Conn, error) {
	return getDialer().dial(ctx, instance)
}

// defaultDialer provides the singleton dialer as a default for dial functinons.
func getDialer() *dialManager {
	once.Do(func() {
		// TODO: Do this better
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		client, err := sqladmin.NewService(context.Background())
		if err != nil {
			panic(err)
		}
		d = &dialManager{
			lock:     &sync.RWMutex{},
			imap:     make(map[string]*instance.Instance),
			sqladmin: client,
			key:      key,
		}

	})
	return d
}

type dialManager struct {
	lock *sync.RWMutex
	imap map[string]*instance.Instance

	sqladmin *sqladmin.Service
	key      *rsa.PrivateKey
}

func (d *dialManager) instance(cn string) (i *instance.Instance, err error) {
	// Check instance cache
	d.lock.RLock()
	i, ok := d.imap[cn]
	d.lock.RUnlock()
	if !ok {
		d.lock.Lock()
		// Create a new instance and store it in the map
		i, err = instance.NewInstance(cn, d.sqladmin, d.key)
		if err != nil {
			d.imap[cn] = i
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
