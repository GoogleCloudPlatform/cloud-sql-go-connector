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

// Package cloudsqlconn contains methods for creating secure, authorized connections to a Cloud SQL instance.
package cloudsqlconn

import (
	"context"
	"net"
	"sync"
)

var (
	once sync.Once
	dm   *Dialer
	dErr error
)

// Dial returns a net.Conn connected to the specified Cloud SQL instance. The instance argument must be the
// instance's connection name, which is in the format "project-name:region:instance-name".
func Dial(ctx context.Context, instance string) (net.Conn, error) {
	d, err := defaultDialer()
	if err != nil {
		return nil, err
	}
	return d.Dial(ctx, instance)
}

// defaultDialer provides the singleton dialer as a default for dial functions.
func defaultDialer() (*Dialer, error) {
	// TODO: Provide functionality for customizing/setting the default dialer
	once.Do(func() {
		dm, dErr = NewDialer()
	})
	return dm, dErr
}
