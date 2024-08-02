// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cloudsql

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"cloud.google.com/go/cloudsqlconn/instance"
)

type fakeResolver struct{}

func (r *fakeResolver) LookupSRV(_ context.Context, _, _, name string) (cname string, addrs []*net.SRV, err error) {
	// For TestDialerSuccessfullyDialsDnsSrvRecord
	if name == "db.example.com" {
		return "", []*net.SRV{
			&net.SRV{Target: "my-project:my-region:my-instance."},
		}, nil
	}
	if name == "db2.example.com" {
		return "", []*net.SRV{
			&net.SRV{Target: "my-project:my-region:my-instance"},
		}, nil
	}
	// For TestDialerFailsDnsSrvRecordMalformed
	if name == "malformed.example.com" {
		return "", []*net.SRV{
			&net.SRV{Target: "an-invalid-instance-name"},
		}, nil
	}
	return "", nil, fmt.Errorf("no resolution for %v", name)
}

func TestDNSInstanceNameResolver_Lookup_Success_SrvRecord(t *testing.T) {
	want, _ := instance.ParseConnName("my-project:my-region:my-instance")

	r := DNSInstanceConnectionNameResolver{
		dnsResolver: &fakeResolver{},
	}
	got, err := r.Resolve(context.Background(), "db.example.com")
	if err != nil {
		t.Fatal("got error", err)
	}
	if got != want {
		t.Fatal("Got", got, "Want", want)
	}

	got, err = r.Resolve(context.Background(), "db2.example.com")
	if err != nil {
		t.Fatal("got error", err)
	}
	if got != want {
		t.Fatal("Got", got, "Want", want)
	}
}

func TestDNSInstanceNameResolver_Lookup_Fails_SrvRecordMissing(t *testing.T) {
	r := DNSInstanceConnectionNameResolver{
		dnsResolver: &fakeResolver{},
	}
	_, err := r.Resolve(context.Background(), "doesnt-exist.example.com")

	wantMsg := "unable to resolve SRV record for \"doesnt-exist.example.com\""
	if !strings.Contains(err.Error(), wantMsg) {
		t.Fatalf("want = %v, got = %v", wantMsg, err)
	}
}

func TestDNSInstanceNameResolver_Lookup_Fails_SrvRecordMalformed(t *testing.T) {
	r := DNSInstanceConnectionNameResolver{
		dnsResolver: &fakeResolver{},
	}
	_, err := r.Resolve(context.Background(), "malformed.example.com")
	wantMsg := "unable to parse SRV for \"malformed.example.com\""
	if !strings.Contains(err.Error(), wantMsg) {
		t.Fatalf("want = %v, got = %v", wantMsg, err)
	}
}
