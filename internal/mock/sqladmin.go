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
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"google.golang.org/api/option"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

// httpClient returns an *http.Client, URL, and cleanup function. The http.Client is
// configured to connect to test SSL Server at the returned URL. This server will
// respond to HTTP requests defined, or return a 5xx server error for unexpected ones.
// The cleanup function will close the server, and return an error if any expected calls
// weren't received.
func httpClient(requests ...*Request) (*http.Client, string, func() error) {
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
			resp.WriteHeader(http.StatusNotImplemented)
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

// matches returns true if a given http.Request should be handled by this Request.
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

// InstanceGetSuccess returns a Request that responds to the `instance.get` SQL Admin
// endpoint. It responds with a "StatusOK" and a DatabaseInstance object.
//
// https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances/get
func InstanceGetSuccess(i FakeCSQLInstance, ct int) *Request {
	var ips []*sqladmin.IpMapping
	for ipType, addr := range i.ipAddrs {
		if ipType == "PUBLIC" {
			ips = append(ips, &sqladmin.IpMapping{IpAddress: addr, Type: "PRIMARY"})
			continue
		}
		if ipType == "PRIVATE" {
			ips = append(ips, &sqladmin.IpMapping{IpAddress: addr, Type: "PRIVATE"})
		}
	}
	certBytes, err := i.signedCert()
	if err != nil {
		panic(err)
	}
	db := &sqladmin.ConnectSettings{
		BackendType:     i.backendType,
		DatabaseVersion: i.dbVersion,
		DnsName:         i.DNSName,
		IpAddresses:     ips,
		Region:          i.region,
		ServerCaCert:    &sqladmin.SslCert{Cert: string(certBytes)},
	}

	r := &Request{
		reqMethod: http.MethodGet,
		reqPath:   fmt.Sprintf("/sql/v1beta4/projects/%s/instances/%s/connectSettings", i.project, i.name),
		reqCt:     ct,
		handle: func(resp http.ResponseWriter, req *http.Request) {
			b, err := db.MarshalJSON()
			if err != nil {
				http.Error(resp, err.Error(), http.StatusInternalServerError)
				return
			}
			resp.WriteHeader(http.StatusOK)
			resp.Write(b)
		},
	}
	return r
}

// CreateEphemeralSuccess returns a Request that responds to the
// `connect.generateEphemeralCert` SQL Admin endpoint. It responds with a
// "StatusOK" and a SslCerts object.
//
// https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/connect/generateEphemeralCert
func CreateEphemeralSuccess(i FakeCSQLInstance, ct int) *Request {
	r := &Request{
		reqMethod: http.MethodPost,
		reqPath:   fmt.Sprintf("/sql/v1beta4/projects/%s/instances/%s:generateEphemeralCert", i.project, i.name),
		reqCt:     ct,
		handle: func(resp http.ResponseWriter, req *http.Request) {
			// Read the body from the request.
			b, err := ioutil.ReadAll(req.Body)
			defer req.Body.Close()
			if err != nil {
				http.Error(resp, fmt.Errorf("unable to read body: %w", err).Error(), http.StatusBadRequest)
				return
			}
			var eR sqladmin.GenerateEphemeralCertRequest
			err = json.Unmarshal(b, &eR)
			if err != nil {
				http.Error(resp, fmt.Errorf("invalid or unexpected json: %w", err).Error(), http.StatusBadRequest)
				return
			}
			// Extract the certificate from the request.
			bl, _ := pem.Decode([]byte(eR.PublicKey))
			if bl == nil {
				http.Error(resp, fmt.Errorf("unable to decode PublicKey: %w", err).Error(), http.StatusBadRequest)
				return
			}
			pubKey, err := x509.ParsePKIXPublicKey(bl.Bytes)
			if err != nil {
				http.Error(resp, fmt.Errorf("unable to decode PublicKey: %w", err).Error(), http.StatusBadRequest)
				return
			}

			certBytes, err := i.clientCert(pubKey.(*rsa.PublicKey))
			if err != nil {
				http.Error(resp, fmt.Errorf("failed to sign client certificate: %v", err).Error(), http.StatusBadRequest)
				return
			}

			// Return the signed cert to the client.
			c := &sqladmin.SslCert{
				Cert:           string(certBytes),
				CommonName:     "Google Cloud SQL Client",
				CreateTime:     time.Now().Format(time.RFC3339),
				ExpirationTime: i.Cert.NotAfter.Format(time.RFC3339),
				Instance:       i.name,
			}
			certResp := sqladmin.GenerateEphemeralCertResponse{
				EphemeralCert: c,
			}
			b, err = certResp.MarshalJSON()
			if err != nil {
				http.Error(resp, fmt.Errorf("unable to encode response: %w", err).Error(), http.StatusInternalServerError)
				return
			}
			resp.WriteHeader(http.StatusOK)
			resp.Write(b)
		},
	}
	return r
}

// NewSQLAdminService creates a SQL Admin API service backed by a mock HTTP
// backend. Callers should use the cleanup function to close down the server. If
// the cleanup function returns an error, a caller has not exercised all the
// registered requests.
func NewSQLAdminService(ctx context.Context, reqs ...*Request) (*sqladmin.Service, func() error, error) {
	mc, url, cleanup := httpClient(reqs...)
	client, err := sqladmin.NewService(
		ctx,
		option.WithHTTPClient(mc),
		option.WithEndpoint(url),
	)
	return client, cleanup, err
}
