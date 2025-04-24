// Copyright 2025 Google LLC
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
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	"cloud.google.com/go/cloudsqlconn/instance"
	"cloud.google.com/go/cloudsqlconn/internal/mock"
)

func TestVerifyCertificate(t *testing.T) {
	tcs := []struct {
		desc       string
		serverName string // verify input server dns name
		icn        string // verify input instance connection name
		cn         string // cert CN
		san        string // cert SAN
		valid      bool   // wants validation to succeed
	}{
		{
			desc:  "cn match",
			icn:   "myProject:myRegion:myInstance",
			cn:    "myProject:myInstance",
			valid: true,
		},
		{
			desc:  "cn no match",
			icn:   "myProject:myRegion:badInstance",
			cn:    "myProject:myInstance",
			valid: false,
		},
		{
			desc:  "cn empty",
			icn:   "myProject:myRegion:myInstance",
			san:   "db.example.com",
			valid: false,
		},
		{
			desc:       "san match",
			serverName: "db.example.com",
			icn:        "myProject:myRegion:myInstance",
			san:        "db.example.com",
			valid:      true,
		},
		{
			desc:       "san no match",
			serverName: "bad.example.com",
			icn:        "myProject:myRegion:myInstance",
			san:        "db.example.com",
			valid:      false,
		},
		{
			desc:       "san empty match",
			serverName: "empty.example.com",
			icn:        "myProject:myRegion:myInstance",
			cn:         "",
			valid:      false,
		},
		{
			desc:       "san match with cn present",
			serverName: "db.example.com",
			icn:        "myProject:myRegion:myInstance",
			san:        "db.example.com",
			cn:         "myProject:myInstance",
			valid:      true,
		},
		{
			desc:       "san no match fallback to cn",
			serverName: "db.example.com",
			icn:        "myProject:myRegion:myInstance",
			san:        "other.example.com",
			cn:         "myProject:myInstance",
			valid:      true,
		},
		{
			desc:       "san empty match fallback to cn",
			serverName: "db.example.com",
			icn:        "myProject:myRegion:myInstance",
			cn:         "myProject:myInstance",
			valid:      true,
		},
		{
			desc:       "san no match fallback to cn and fail",
			serverName: "db.example.com",
			icn:        "myProject:myRegion:badInstance",
			san:        "other.example.com",
			cn:         "myProject:myInstance",
			valid:      false,
		},
	}

	tlsCerts := mock.NewTLSCertificates("myProject", "myInstance", nil, time.Now().Add(time.Hour))

	for _, tc := range tcs {
		for _, useCAS := range []string{"legacy", "cas"} {
			t.Run(fmt.Sprintf(

				"%s %s", tc.desc, useCAS), func(t *testing.T) {
				var sans []string
				if tc.san != "" {
					sans = []string{tc.san}
				}
				var serverChain []*x509.Certificate
				if useCAS == "cas" {
					serverChain = tlsCerts.CreateCASServerChain(tc.cn, sans)
				} else {
					serverChain = tlsCerts.CreateServerChain(tc.cn, sans)
				}

				icn, _ := instance.ParseConnName(tc.icn)

				serverChainRaw := make([][]byte, len(serverChain))
				for i, cert := range serverChain {
					serverChainRaw[i] = cert.Raw
				}

				roots := x509.NewCertPool()
				for i := 1; i < len(serverChain); i++ {
					roots.AddCert(serverChain[i])
				}

				verifyFunc := verifyPeerCertificateFunc(tc.serverName, icn, roots)
				err := verifyFunc(serverChainRaw, nil)

				if err != nil && tc.valid {
					t.Fatalf("want no error, got %v", err)
				}
				if err == nil && !tc.valid {
					t.Fatal("want error, got no error")
				}

			})
		}
	}
}
