// Copyright 2023 Google LLC
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

package instance

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"cloud.google.com/go/cloudsqlconn/errtype"
)

var (
	// Instance connection name is the format <PROJECT>:<REGION>:<INSTANCE>
	// Additionally, we have to support legacy "domain-scoped" projects
	// (e.g. "google.com:PROJECT")
	connNameRegex = regexp.MustCompile("([^:]+(:[^:]+)?):([^:]+):([^:]+)")
	// The domain name pattern in accordance with RFC 1035, RFC 1123 and RFC 2181.
	domainNameRegex = regexp.MustCompile(`^(?:[_a-z0-9](?:[_a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?)?$`)

	instanceDNSSuffixRegex = regexp.MustCompile(`\.sql(-[a-zA-Z0-9_]+)?\.goog\.?$`)
	globalInstanceDNSRegex = regexp.MustCompile(`\.global\.sql(-[a-zA-Z0-9_]+)?\.goog\.?$`)
)

// ConnName represents the "instance connection name", in the format
// "project:region:name".
type ConnName struct {
	project    string
	region     string
	name       string
	domainName string
}

func (c *ConnName) String() string {
	if c.domainName != "" {
		return fmt.Sprintf("%s -> %s:%s:%s", c.domainName, c.project, c.region, c.name)
	}
	return fmt.Sprintf("%s:%s:%s", c.project, c.region, c.name)
}

// Project returns the project within which the Cloud SQL instance runs.
func (c *ConnName) Project() string {
	return c.project
}

// Region returns the region where the Cloud SQL instance runs.
func (c *ConnName) Region() string {
	return c.region
}

// Name returns the Cloud SQL instance name
func (c *ConnName) Name() string {
	return c.name
}

// DomainName returns the domain name for this instance
func (c *ConnName) DomainName() string {
	return c.domainName
}

// HasDomainName returns whether the Cloud SQL instance has a domain name
func (c *ConnName) HasDomainName() bool {
	return c.domainName != ""
}

// IsValidDomain validates that a string is a well-formed domain name
func IsValidDomain(dn string) bool {
	b := []byte(dn)
	m := domainNameRegex.FindSubmatch(b)
	if m == nil {
		return false
	}
	return true
}

// ParseConnName initializes a new ConnName struct.
func ParseConnName(cn string) (ConnName, error) {
	return ParseConnNameWithDomainName(cn, "")
}

// ParseConnNameWithDomainName initializes a new ConnName struct,
// also setting the domain name.
func ParseConnNameWithDomainName(cn string, dn string) (ConnName, error) {
	b := []byte(cn)
	m := connNameRegex.FindSubmatch(b)
	if m == nil {
		err := errtype.NewConfigError(
			"invalid instance connection name, expected PROJECT:REGION:INSTANCE",
			cn,
		)
		return ConnName{}, err
	}

	c := ConnName{
		project:    string(m[1]),
		region:     string(m[3]),
		name:       string(m[4]),
		domainName: dn,
	}
	return c, nil
}

// ConnectionNameResolver resolves the connection name string into a valid
// instance name. This allows an application to replace the default
// resolver with a custom implementation.
type ConnectionNameResolver interface {
	// Resolve accepts a name, and returns a ConnName with the instance
	// connection string for the name. If the name cannot be resolved, returns
	// an error.
	Resolve(ctx context.Context, name string) (ConnName, error)
}

// ParseInstanceDNSName parses a DNS name into its constituent parts.
// Instance DNS names follow this template:
// {instance-dns-label}.{project-dns-label}.{cloud-region}.{dns-suffix}
// Suffix is one of: sql.goog, sql-psa.goog, sql-psc.goog (with optional trailing dot).
// This returns ok == false when the region is "global"
func ParseInstanceDNSName(dnsName string) (instanceLabel, projectLabel, region, suffix string, ok bool) {
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

	// Validate region != "global". "global" is used for redirect to write endpoint DNS
	if region == "global" {
		return "", "", "", "", false
	}

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

// IsInstanceDNSName returns true if the domain name matches the well-known
// Cloud SQL instance DNS name pattern.
func IsInstanceDNSName(dnsName string) bool {
	dnsName = strings.ToLower(dnsName)
	return instanceDNSSuffixRegex.MatchString(dnsName) && !globalInstanceDNSRegex.MatchString(dnsName)
}
