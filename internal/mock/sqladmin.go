// Copyright 2021 Google LLC

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mock

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"

	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

// HttpClient returns an *http.Client, URL, and cleanup function. The http.Client is
// configured to connect to test SSL Server at the returned URL. This server will
// respond to HTTP requests defined as "expected", or return a 5xx server error for
// unexpected ones. The cleanup function will close the server, and return an error if
// any expected calls weren't received.
func HttpClient(expected ...*Expected) (*http.Client, string, func() error) {
	// Create a TLS Server that responses to the requests defined
	s := httptest.NewTLSServer(http.HandlerFunc(
		func(resp http.ResponseWriter, req *http.Request) {
			for _, e := range expected {
				if r := e.handle(req); r != nil {
					resp.WriteHeader(r.statusCode)
					resp.Write(r.body)
					return
				}
			}
			// Unexpected requests should throw an error
			resp.WriteHeader(http.StatusInternalServerError)
			// TODO: follow error format better?
			resp.Write([]byte(fmt.Sprintf("unexpected request sent to mock client: %v", req)))
		},
	))
	// cleanup stops the test server and checks for uncalled requests
	cleanup := func() error {
		s.Close()
		for i, e := range expected {
			if e.ct > 0 {
				return fmt.Errorf("%d calls left for specified call in pos %d: %v", e.ct, i, e)
			}
		}
		return nil
	}

	return s.Client(), s.URL, cleanup
}

// Expected represents a HTTP request for a test Server to receive.
type Expected struct {
	matchFn func(*http.Request) bool
	respFn  func(*http.Request) *resp

	mu sync.Mutex
	// ct is the number of times this call can be exercised.
	ct int
}

type resp struct {
	statusCode int
	body       []byte
}

// Returns a request if the call was handled, otherwise nil.
func (e *Expected) handle(r *http.Request) *resp {
	if e.matchFn(r) {
		e.mu.Lock()
		defer e.mu.Unlock()
		if e.ct > 0 {
			e.ct--
			return e.respFn(r)
		}
	}
	return nil
}

// InstanceGetSuccess defines an expected "instances.get" sqladmin operation and returns
// a generic DatabaseInstance object.
func InstanceGetSuccess(project, region, name string, ct int) *Expected {
	return &Expected{
		matchFn: func(r *http.Request) bool {
			return r.Method == http.MethodGet && r.URL.Path == fmt.Sprintf("/sql/v1beta4/projects/%s/instances/%s", project, name)
		},
		respFn: func(r *http.Request) *resp {
			db := sqladmin.DatabaseInstance{
				BackendType:     "SECOND_GEN",
				ConnectionName:  fmt.Sprintf("%s:%s:%s", project, region, name),
				DatabaseVersion: "POSTGRES_12",
				Project:         project,
				Region:          region,
				Name:            name,
				IpAddresses: []*sqladmin.IpMapping{
					{
						IpAddress: "127.0.0.1",
						Type:      "PRIMARY",
					},
				},
				ServerCaCert: &sqladmin.SslCert{Cert: ""},
			}
			b, err := db.MarshalJSON()
			if err != nil {
				panic(err)
			}
			return &resp{
				statusCode: http.StatusOK,
				body:       b,
			}
		},
		mu: sync.Mutex{},
		ct: ct,
	}
}
