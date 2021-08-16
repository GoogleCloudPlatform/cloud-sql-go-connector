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
	"net"
	"sync"
)

var (
	once          sync.Once
	defaultDialer *Dialer
	dErr          error
)

// Dial returns a net.Conn connected to the specified Cloud SQL instance. The
// instance argument must be the instance's connection name, which is in the
// format "project-name:region:instance-name". Dial is a convenience wrapper
// that instantiates a Dialer and dials the specified instance. The dialer's
// goroutine that keeps an instance's connection data fresh is leaked. Callers
// who are concerned about performance should instantiate a dialer on their own
// and close it when finished.
func Dial(ctx context.Context, instance string) (net.Conn, error) {
	d, err := getDefaultDialer()
	if err != nil {
		return nil, err
	}
	return d.Dial(ctx, instance)
}

// getDefaultDialer provides the singleton dialer as a default for dial functions.
func getDefaultDialer() (*Dialer, error) {
	// TODO: Provide functionality for customizing/setting the default dialer
	once.Do(func() {
		defaultDialer, dErr = NewDialer(context.Background())
	})
	return defaultDialer, dErr
}
