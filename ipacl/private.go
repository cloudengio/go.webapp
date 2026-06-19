// Copyright 2025 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package ipacl

import (
	"fmt"
	"net"
	"net/netip"

	"cloudeng.io/net/netutil"
	"github.com/gaissmai/bart"
)

// IsPrivateIP checks if the given IP address string is a private IP address.
// It returns true if the IP address is in a private range (RFC 1918 or RFC 4193)
// or is a loopback address. It also supports CIDR prefixes.
func IsPrivateIP(ipStr string) bool {
	cleaned := ipStr
	if len(cleaned) > 1 && cleaned[0] == '[' && cleaned[len(cleaned)-1] == ']' {
		cleaned = cleaned[1 : len(cleaned)-1]
	}

	if host, _, err := net.SplitHostPort(cleaned); err == nil {
		cleaned = host
	}

	if prefix, err := netip.ParsePrefix(cleaned); err == nil {
		addr := prefix.Addr()
		return addr.IsPrivate() || addr.IsLoopback()
	}

	addr, err := netip.ParseAddr(cleaned)
	if err != nil {
		return false
	}
	return addr.IsPrivate() || addr.IsLoopback()
}

// PrivateSubnet represents a set of private IP addresses defined by CIDR prefixes.
type PrivateSubnet struct {
	acl *bart.Lite
}

// NewPrivateSubnet creates a new PrivateSubnet from a list of CIDR prefixes or IP addresses.
func NewPrivateSubnet(addrs ...string) (*PrivateSubnet, error) {
	acl := &bart.Lite{}
	for _, addr := range addrs {
		if !IsPrivateIP(addr) {
			return nil, fmt.Errorf("address %q is not a private IP address", addr)
		}
		p, err := netutil.ParseAddrOrPrefix(addr)
		if err != nil {
			return nil, err
		}
		acl.Insert(p)
	}
	return &PrivateSubnet{acl: acl}, nil
}

// Contains checks if the given address (which may include an optional port) is
// contained within the private subnet.
func (ps *PrivateSubnet) Contains(addr string) bool {
	ip, err := parseOptionalPort(addr)
	if err != nil {
		return false
	}
	return ps.acl.Contains(ip)
}
