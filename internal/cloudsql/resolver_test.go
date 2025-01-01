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
	"strings"
	"testing"

	"cloud.google.com/go/cloudsqlconn/instance"
)

type fakeResolver struct {
	name  string
	value string
}

func (r *fakeResolver) LookupTXT(_ context.Context, name string) (addrs []string, err error) {
	if name == r.name {
		return []string{r.value}, nil
	}
	return nil, fmt.Errorf("no resolution for %v", name)
}

func TestDNSInstanceNameResolver_Lookup_Success_TxtRecord(t *testing.T) {
	want, _ := instance.ParseConnNameWithDomainName("my-project:my-region:my-instance", "db.example.com")

	r := DNSInstanceConnectionNameResolver{
		dnsResolver: &fakeResolver{
			name:  "db.example.com",
			value: "my-project:my-region:my-instance",
		},
	}
	got, err := r.Resolve(context.Background(), "db.example.com")
	if err != nil {
		t.Fatal("got error", err)
	}
	if got != want {
		t.Fatal("Got", got, "Want", want)
	}

}

func TestDNSInstanceNameResolver_Lookup_Fails_TxtRecordMissing(t *testing.T) {
	r := DNSInstanceConnectionNameResolver{
		dnsResolver: &fakeResolver{},
	}
	_, err := r.Resolve(context.Background(), "doesnt-exist.example.com")

	wantMsg := "unable to resolve TXT record for \"doesnt-exist.example.com\""
	if !strings.Contains(err.Error(), wantMsg) {
		t.Fatalf("want = %v, got = %v", wantMsg, err)
	}
}

func TestDNSInstanceNameResolver_Lookup_Fails_TxtRecordMalformed(t *testing.T) {
	r := DNSInstanceConnectionNameResolver{
		dnsResolver: &fakeResolver{
			name:  "malformed.example.com",
			value: "invalid-instance-name",
		},
	}
	_, err := r.Resolve(context.Background(), "malformed.example.com")
	wantMsg := "unable to parse TXT for \"malformed.example.com\""
	if !strings.Contains(err.Error(), wantMsg) {
		t.Fatalf("want = %v, got = %v", wantMsg, err)
	}
}
