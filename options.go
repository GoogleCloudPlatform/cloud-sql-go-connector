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
	"crypto/rsa"
	"time"

	"cloud.google.com/cloudsqlconn/internal/cloudsql"
	"golang.org/x/oauth2"
	apiopt "google.golang.org/api/option"
)

// A DialerOption is an option for configuring a Dialer.
type DialerOption func(d *dialerConfig)

type dialerConfig struct {
	rsaKey         *rsa.PrivateKey
	sqladminOpts   []apiopt.ClientOption
	dialOpts       []DialOption
	refreshTimeout time.Duration
}

// DialerOptions turns a list of DialerOption instances into an DialerOption.
func DialerOptions(opts ...DialerOption) DialerOption {
	return func(d *dialerConfig) {
		for _, opt := range opts {
			opt(d)
		}
	}
}

// WithCredentialsFile returns a DialerOption that specifies a service account or refresh token JSON credentials file to be used as the basis for authentication.
func WithCredentialsFile(filename string) DialerOption {
	return func(d *dialerConfig) {
		d.sqladminOpts = append(d.sqladminOpts, apiopt.WithCredentialsFile(filename))
	}
}

// WithCredentialsJSON returns a DialerOption that specifies a service account or refresh token JSON credentials to be used as the basis for authentication.
func WithCredentialsJSON(p []byte) DialerOption {
	return func(d *dialerConfig) {
		d.sqladminOpts = append(d.sqladminOpts, apiopt.WithCredentialsJSON(p))
	}
}

// WithDefaultDialOption returns a DialerOption that specifies the default DialOptions used.
func WithDefaultDialOptions(opts ...DialOption) DialerOption {
	return func(d *dialerConfig) {
		d.dialOpts = append(d.dialOpts, opts...)
	}
}

// WithTokenSource returns a DialerOption that specifies an OAuth2 token source to be used as the basis for authentication.
func WithTokenSource(s oauth2.TokenSource) DialerOption {
	return func(d *dialerConfig) {
		d.sqladminOpts = append(d.sqladminOpts, apiopt.WithTokenSource(s))
	}
}

// WithRSAKey returns a DialerOption that specifies a rsa.PrivateKey used to represent the client.
func WithRSAKey(k *rsa.PrivateKey) DialerOption {
	return func(d *dialerConfig) {
		d.rsaKey = k
	}
}

// WithRefreshTimeout returns a DialerOption that sets a timeout on refresh operations. Defaults to 30s.
func WithRefreshTimeout(t time.Duration) DialerOption {
	return func(d *dialerConfig) {
		d.refreshTimeout = t
	}
}

// A DialOption is an option for configuring how a Dialer's Dial call is executed.
type DialOption func(d *dialCfg)

type dialCfg struct {
	tcpKeepAlive time.Duration
	ipType       string
}

// DialOptions turns a list of DialOption instances into an DialOption.
func DialOptions(opts ...DialOption) DialOption {
	return func(cfg *dialCfg) {
		for _, opt := range opts {
			opt(cfg)
		}
	}
}

// WithTCPKeepAlive returns a DialOption that specifies the tcp keep alive period for the connection returned by Dial.
func WithTCPKeepAlive(d time.Duration) DialOption {
	return func(cfg *dialCfg) {
		cfg.tcpKeepAlive = d
	}
}

// WithPublicIP returns a DialOption that specifies a public IP will be used to connect.
func WithPublicIP() DialOption {
	return func(cfg *dialCfg) {
		cfg.ipType = cloudsql.PublicIP
	}
}

// WithPrivateIP returns a DialOption that specifies a private IP (VPC) will be used to connect.
func WithPrivateIP() DialOption {
	return func(cfg *dialCfg) {
		cfg.ipType = cloudsql.PrivateIP
	}
}
