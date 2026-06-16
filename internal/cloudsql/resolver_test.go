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
	"cloud.google.com/go/cloudsqlconn/internal/mock"
)

type fakeResolver struct {
	txtEntries   map[string]string
	cnameEntries map[string]string
}

func (r *fakeResolver) LookupTXT(_ context.Context, name string) (addrs []string, err error) {
	if val, ok := r.txtEntries[name]; ok {
		return []string{val}, nil
	}
	return nil, fmt.Errorf("no TXT resolution for %q", name)
}

func (r *fakeResolver) LookupHost(_ context.Context, name string) (addrs []string, err error) {
	return nil, fmt.Errorf("no host resolution for %q", name)
}

func (r *fakeResolver) LookupCNAME(_ context.Context, name string) (string, error) {
	if val, ok := r.cnameEntries[name]; ok {
		return val, nil
	}
	return "", fmt.Errorf("no CNAME resolution for %q", name)
}

func TestDNSInstanceNameResolver_Lookup_Success_TxtRecord(t *testing.T) {
	want, _ := instance.ParseConnNameWithDomainName("my-project:my-region:my-instance", "db.example.com")

	r := DNSInstanceConnectionNameResolver{
		dnsResolver: &fakeResolver{
			txtEntries: map[string]string{
				"db.example.com": "my-project:my-region:my-instance",
			},
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
			txtEntries: map[string]string{
				"malformed.example.com": "invalid-instance-name",
			},
		},
	}
	_, err := r.Resolve(context.Background(), "malformed.example.com")
	wantMsg := "unable to parse TXT for \"malformed.example.com\""
	if !strings.Contains(err.Error(), wantMsg) {
		t.Fatalf("want = %v, got = %v", wantMsg, err)
	}
}

func TestDNSInstanceNameResolver_Lookup_Success_DirectPSC(t *testing.T) {
	dnsName := "0123456789ab.fedcba9876543.europe-north2.sql-psc.goog"
	realConnName := "my-project:europe-north2:my-instance"
	want, _ := instance.ParseConnNameWithDomainName(realConnName, dnsName)

	client, cleanup, err := mock.NewSQLAdminService(
		context.Background(),
		mock.ResolveConnectSettingsSuccess(dnsName+".", "europe-north2", realConnName, 1),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	r := DNSInstanceConnectionNameResolver{
		dnsResolver: &fakeResolver{},
		client:      client,
	}
	got, err := r.Resolve(context.Background(), dnsName)
	if err != nil {
		t.Fatal("got error", err)
	}
	if got != want {
		t.Fatal("Got", got, "Want", want)
	}
}

func TestDNSInstanceNameResolver_Lookup_Success_CnamePSC(t *testing.T) {
	dnsName := "db.example.com"
	cnameTarget := "0123456789ab.fedcba9876543.europe-north2.sql-psc.goog"
	realConnName := "my-project:europe-north2:my-instance"
	want, _ := instance.ParseConnNameWithDomainName(realConnName, dnsName) // Preserves original dnsName!

	client, cleanup, err := mock.NewSQLAdminService(
		context.Background(),
		mock.ResolveConnectSettingsSuccess(cnameTarget+".", "europe-north2", realConnName, 1),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	r := DNSInstanceConnectionNameResolver{
		dnsResolver: &fakeResolver{
			cnameEntries: map[string]string{
				dnsName: cnameTarget,
			},
		},
		client: client,
	}
	got, err := r.Resolve(context.Background(), dnsName)
	if err != nil {
		t.Fatal("got error", err)
	}
	if got != want {
		t.Fatal("Got", got, "Want", want)
	}
}

func TestDNSInstanceNameResolver_Lookup_Fails_InvalidPattern(t *testing.T) {
	invalidDNSNames := []string{
		"0123456789ab.fedcba9876543.europe-north2.sql-psc.goog.com", // wrong suffix domain
		"0123456789ag.fedcba9876543.europe-north2.sql-psc.goog",     // non-hex char 'g' in hash
		"0123456789a.fedcba9876543.europe-north2.sql-psc.goog",      // wrong hash length (11)
		"0123456789abc.fedcba9876543.europe-north2.sql-psc.goog",    // wrong hash length (13)
		"0123456789ab.fedcba9876543.europenorth2.sql-psc.goog",      // region has no hyphen
	}

	for _, dnsName := range invalidDNSNames {
		r := DNSInstanceConnectionNameResolver{
			dnsResolver: &fakeResolver{},
		}
		_, err := r.Resolve(context.Background(), dnsName)
		if err == nil {
			t.Errorf("expected error for invalid DNS name: %q", dnsName)
		}
	}
}

func TestDNSInstanceNameResolver_Lookup_Success_CnameChainPSC(t *testing.T) {
	dnsName := "name1.example.com"
	cname2 := "name2.example.com"
	cnameTarget := "0123456789ab.fedcba9876543.europe-north2.sql-psc.goog"
	realConnName := "my-project:europe-north2:my-instance"
	want, _ := instance.ParseConnNameWithDomainName(realConnName, dnsName) // Preserves original dnsName!

	client, cleanup, err := mock.NewSQLAdminService(
		context.Background(),
		mock.ResolveConnectSettingsSuccess(cnameTarget+".", "europe-north2", realConnName, 1),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	r := DNSInstanceConnectionNameResolver{
		dnsResolver: &fakeResolver{
			cnameEntries: map[string]string{
				dnsName: cname2,
				cname2:  cnameTarget,
			},
		},
		client: client,
	}
	got, err := r.Resolve(context.Background(), dnsName)
	if err != nil {
		t.Fatal("got error", err)
	}
	if got != want {
		t.Fatal("Got", got, "Want", want)
	}
}

func TestDNSInstanceNameResolver_Lookup_Success_CnameChainTxt(t *testing.T) {
	dnsName := "name1.example.com"
	cname2 := "name2.example.com"
	cname3 := "name3.example.com"
	want, _ := instance.ParseConnNameWithDomainName("my-project:my-region:my-instance", cname3)

	r := DNSInstanceConnectionNameResolver{
		dnsResolver: &fakeResolver{
			cnameEntries: map[string]string{
				dnsName: cname2,
				cname2:  cname3,
			},
			txtEntries: map[string]string{
				cname3: "my-project:my-region:my-instance",
			},
		},
	}
	got, err := r.Resolve(context.Background(), dnsName)
	if err != nil {
		t.Fatal("got error", err)
	}
	if got != want {
		t.Fatal("Got", got, "Want", want)
	}
}

func TestDNSInstanceNameResolver_Lookup_Fails_CnameLoop(t *testing.T) {
	dnsName := "name1.example.com"
	cname2 := "name2.example.com"

	r := DNSInstanceConnectionNameResolver{
		dnsResolver: &fakeResolver{
			cnameEntries: map[string]string{
				dnsName: cname2,
				cname2:  dnsName, // Loop!
			},
		},
	}
	_, err := r.Resolve(context.Background(), dnsName)
	if err == nil {
		t.Fatal("expected error due to CNAME loop")
	}
	wantMsg := "cname lookup limit exceeded"
	if !strings.Contains(err.Error(), wantMsg) {
		t.Fatalf("want = %v, got = %v", wantMsg, err)
	}
}
