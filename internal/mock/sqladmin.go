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
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"

	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

// HTTPClient returns an *http.Client, URL, and cleanup function. The http.Client is
// configured to connect to test SSL Server at the returned URL. This server will
// respond to HTTP requests defined, or return a 5xx server error for unexpected ones.
// The cleanup function will close the server, and return an error if any expected calls
// weren't received.
func HTTPClient(requests ...*Request) (*http.Client, string, func() error) {
	// Create a TLS Server that responses to the requests defined
	s := httptest.NewTLSServer(http.HandlerFunc(
		func(resp http.ResponseWriter, req *http.Request) {
			for _, r := range requests {
				if r.matches(req) {
					r.handle(resp, req)
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
		for i, e := range requests {
			if e.reqCt > 0 {
				return fmt.Errorf("%d calls left for specified call in pos %d: %v", e.reqCt, i, e)
			}
		}
		return nil
	}

	return s.Client(), s.URL, cleanup

}

// Request represents a HTTP request for a test Server to mock responses for.
//
// Use NewRequest to initialize new Requests.
type Request struct {
	sync.Mutex

	reqMethod string
	reqPath   string
	reqCt     int

	handle func(resp http.ResponseWriter, req *http.Request)
}

// matches returns true if a given http.Request should be handled by this MockRequest.
func (r *Request) matches(hR *http.Request) bool {
	r.Lock()
	defer r.Unlock()
	if r.reqMethod != "" && r.reqMethod != hR.Method {
		return false
	}
	if r.reqPath != "" && r.reqPath != hR.URL.Path {
		return false
	}
	if r.reqCt <= 0 {
		return false
	}
	r.reqCt--
	return true
}

// InstanceGetSuccess returns a MockRequest that responds to the `instance.get` SQLAdmin
// endpoint. It responds with a "StatusOK" and a DatabaseInstance object.
//
// https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances/get
func InstanceGetSuccess(i CloudSQLInstance, ct int) *Request {
	// Turn instance keys/certs into PEM encoded versions needed for response
	certBytes, err := x509.CreateCertificate(
		rand.Reader, i.cert, i.cert, &i.privKey.PublicKey, i.privKey)
	if err != nil {
		panic(err)
	}
	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	db := &sqladmin.DatabaseInstance{
		BackendType:     "SECOND_GEN",
		ConnectionName:  fmt.Sprintf("%s:%s:%s", i.project, i.region, i.name),
		DatabaseVersion: i.dbVersion,
		Project:         i.project,
		Region:          i.region,
		Name:            i.name,
		IpAddresses: []*sqladmin.IpMapping{
			{
				IpAddress: "127.0.0.1",
				Type:      "PRIMARY",
			},
		},
		ServerCaCert: &sqladmin.SslCert{Cert: certPEM.String()},
	}

	r := &Request{
		reqMethod: http.MethodGet,
		reqPath:   fmt.Sprintf("/sql/v1beta4/projects/%s/instances/%s", i.project, i.name),
		reqCt:     ct,
		handle: func(resp http.ResponseWriter, req *http.Request) {
			resp.WriteHeader(http.StatusOK)
			b, err := db.MarshalJSON()
			if err != nil {
				panic(err)
			}
			resp.Write(b)
		},
	}
	return r
}
