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
	"sort"
	"strings"

	"cloud.google.com/go/cloudsqlconn/errtype"
	"cloud.google.com/go/cloudsqlconn/instance"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

// DefaultResolver simply parses instance names.
var DefaultResolver = &ConnNameResolver{}

// ConnNameResolver simply parses instance names. Implements
// InstanceConnectionNameResolver
type ConnNameResolver struct {
}

// Resolve returns the instance name, possibly using DNS. This will return an
// instance.ConnName or an error if it was unable to resolve an instance name.
func (r *ConnNameResolver) Resolve(_ context.Context, icn string) (instanceName instance.ConnName, err error) {
	return instance.ParseConnName(icn)
}

// NetResolver groups the methods on net.Resolver that are used by the DNS
// resolver implementation. This allows an application to replace the default
// net.DefaultResolver with a custom implementation. For example: the
// application may need to connect to a specific DNS server using a specially
// configured instance of net.Resolver.
type NetResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupHost(ctx context.Context, name string) ([]string, error)
	LookupCNAME(ctx context.Context, name string) (string, error)
}

// NewDNSResolver returns a new DNSInstanceConnectionNameResolver with the
// provided resolver.
func NewDNSResolver(r NetResolver, client *sqladmin.Service) *DNSInstanceConnectionNameResolver {
	return &DNSInstanceConnectionNameResolver{
		dnsResolver: r,
		client:      client,
	}
}

// DNSInstanceConnectionNameResolver can resolve domain names into instance names using
// TXT records in DNS. Implements InstanceConnectionNameResolver
type DNSInstanceConnectionNameResolver struct {
	dnsResolver NetResolver
	client      *sqladmin.Service
}

// Resolve returns the instance name, possibly using DNS. This will return an
// instance.ConnName or an error if it was unable to resolve an instance name.
func (r *DNSInstanceConnectionNameResolver) Resolve(ctx context.Context, icn string) (instance.ConnName, error) {
	current := icn
	var txtErr error

	for depth := 0; depth < 10; depth++ {
		cn, err := instance.ParseConnName(current)
		if err == nil {
			return cn, nil
		}

		// Check if it matches the well-known DNS pattern directly
		if _, _, region, _, ok := parseDNSName(current); ok {
			dnsNameWithDot := current
			if !strings.HasSuffix(dnsNameWithDot, ".") {
				dnsNameWithDot += "."
			}
			db, err := retry50x(ctx, func(ctx2 context.Context) (*sqladmin.ConnectSettings, error) {
				return r.client.Connect.Resolve(
					region, dnsNameWithDot).Context(ctx2).Do()
			}, exponentialBackoff)
			if err != nil {
				return instance.ConnName{}, err
			}

			// Return ConnName using the resolved connection name from the API response
			return instance.ParseConnNameWithDomainName(db.ConnectionName, icn)
		}

		// Check that connection name is a valid DNS domain name.
		if !instance.IsValidDomain(current) {
			return instance.ConnName{}, errtype.NewConfigError(
				"invalid connection name, expected PROJECT:REGION:INSTANCE "+
					"format or valid DNS domain name",
				current,
			)
		}

		// Attempt to query a TXT record
		cn, txtErr = r.queryDNS(ctx, current)
		if txtErr == nil {
			return cn, nil
		}

		// If TXT lookup fails, check CNAME record
		cname, cnameErr := r.dnsResolver.LookupCNAME(ctx, current)
		if cnameErr != nil {
			// If CNAME lookup also fails, return the TXT error
			return instance.ConnName{}, txtErr
		}

		cname = strings.TrimSuffix(cname, ".")
		if cname == current {
			return instance.ConnName{}, fmt.Errorf("cname loop detected for %q", current)
		}
		if !instance.IsValidDomain(cname) {
			return instance.ConnName{}, fmt.Errorf("invalid CNAME target %q for %q", cname, current)
		}

		current = cname
	}

	return instance.ConnName{}, fmt.Errorf("cname lookup limit exceeded (max 10) for %q", icn)
}

// queryDNS attempts to resolve a TXT record for the domain name.
// The DNS TXT record's target field is used as instance name.
//
// This handles several conditions where the DNS records may be missing or
// invalid:
//   - The domain name resolves to 0 DNS records - return an error
//   - Some DNS records to not contain a well-formed instance name - return the
//     first well-formed instance name. If none found return an error.
//   - The domain name resolves to 2 or more DNS record - return first valid
//     record when sorted by priority: lowest value first, then by target:
//     alphabetically.
func (r *DNSInstanceConnectionNameResolver) queryDNS(ctx context.Context, domainName string) (instance.ConnName, error) {
	// Attempt to query the TXT records.
	// This could return a partial error where both err != nil && len(records) > 0.
	records, err := r.dnsResolver.LookupTXT(ctx, domainName)
	// If resolve failed and no records were found, return the error.
	if err != nil {
		return instance.ConnName{}, fmt.Errorf("unable to resolve TXT record for %q: %w", domainName, err)
	}

	// Process the records returning the first valid TXT record.

	// Sort the TXT record values alphabetically by instance name
	sort.Slice(records, func(i, j int) bool {
		return records[i] < records[j]
	})

	var perr error
	// Attempt to parse records, returning the first valid record.
	for _, record := range records {
		// Parse the target as a CN
		cn, parseErr := instance.ParseConnNameWithDomainName(record, domainName)
		if parseErr != nil {
			perr = fmt.Errorf("unable to parse TXT for %q -> %q : %w", domainName, record, parseErr)
			continue
		}
		return cn, nil
	}

	// If all the records failed to parse, return one of the parse errors
	if perr != nil {
		return instance.ConnName{}, perr
	}

	// No records were found, return an error.
	return instance.ConnName{}, fmt.Errorf("no valid TXT records found for %q", domainName)
}

// parseDNSName parses a DNS name into its constituent parts.
// Instance DNS names follow this template:
// {instance-dns-label}.{project-dns-label}.{cloud-region}.{dns-suffix}
// Suffix is one of: sql.goog, sql-psa.goog, sql-psc.goog (with optional trailing dot).
func parseDNSName(dnsName string) (instanceLabel, projectLabel, region, suffix string, ok bool) {
	dnsName = strings.TrimSuffix(dnsName, ".")
	dnsName = strings.ToLower(dnsName)

	parts := strings.Split(dnsName, ".")
	if len(parts) != 5 {
		return "", "", "", "", false
	}

	if parts[4] != "goog" {
		return "", "", "", "", false
	}

	suffixType := parts[3]
	if suffixType != "sql" && suffixType != "sql-psa" && suffixType != "sql-psc" {
		return "", "", "", "", false
	}

	instanceLabel = parts[0]
	projectLabel = parts[1]
	region = parts[2]
	suffix = suffixType + ".goog"

	// Validate labels
	if len(instanceLabel) != 12 {
		return "", "", "", "", false
	}
	for _, c := range instanceLabel {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return "", "", "", "", false
		}
	}

	if !strings.Contains(region, "-") {
		return "", "", "", "", false
	}

	return instanceLabel, projectLabel, region, suffix, true
}
