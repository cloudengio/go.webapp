// Copyright 2025 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package ipacl

import (
	"testing"
)

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		// Private IPv4 (RFC 1918)
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.0.1", true},
		{"192.168.255.255", true},

		// Private IPv4 with Port
		{"10.0.0.1:80", true},
		{"172.16.0.1:443", true},
		{"192.168.1.1:8080", true},

		// Loopback IPv4
		{"127.0.0.1", true},
		{"127.0.0.1:80", true},
		{"127.255.255.255", true},

		// Public IPv4
		{"8.8.8.8", false},
		{"8.8.8.8:53", false},
		{"1.1.1.1", false},
		{"1.1.1.1:443", false},

		// Private IPv6 (Unique Local Addresses - RFC 4193)
		{"fd00::1", true},
		{"fc00::1", true},
		{"[fd00::1]:80", true},

		// Loopback IPv6
		{"::1", true},
		{"[::1]", true},
		{"[::1]:80", true},

		// Public IPv6
		{"2001:db8::1", false},
		{"[2001:db8::1]:443", false},

		// CIDR Prefixes
		{"10.0.0.0/8", true},
		{"172.16.0.0/12", true},
		{"192.168.0.0/16", true},
		{"8.8.8.8/32", false},
		{"fd00::/8", true},
		{"2001:db8::/32", false},

		// Missing Host / Invalid Host
		{"", false},
		{":80", false},
		{"invalid", false},
		{"invalid:80", false},
		{"example.com", false},
		{"example.com:80", false},

		// Missing Port but has colon (trailing colon)
		{"192.168.1.1:", true},
		{"::1:", false}, // invalid IP
	}

	for _, tc := range tests {
		t.Run(tc.ip, func(t *testing.T) {
			if got := IsPrivateIP(tc.ip); got != tc.want {
				t.Errorf("IsPrivateIP(%q) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

func TestPrivateSubnet(t *testing.T) {
	// Construct a PrivateSubnet with various private CIDRs and IPs
	ps, err := NewPrivateSubnet("10.0.0.0/8", "192.168.1.0/24", "::1", "fd00::/8")
	if err != nil {
		t.Fatalf("failed to create PrivateSubnet: %v", err)
	}

	tests := []struct {
		addr string
		want bool
	}{
		// Matching CIDR ranges
		{"10.0.0.1", true},
		{"10.1.2.3:80", true},
		{"192.168.1.50", true},
		{"192.168.1.200:443", true},
		{"::1", true},
		{"[::1]:8080", true},
		{"fd00::1", true},
		{"[fd00::100]:443", true},

		// Outside ranges
		{"192.168.2.1", false},
		{"192.168.2.1:80", false},
		{"8.8.8.8", false},
		{"8.8.8.8:53", false},
		{"2001:db8::1", false},
		{"[2001:db8::1]:80", false},
		{"invalid", false},
	}

	for _, tc := range tests {
		t.Run(tc.addr, func(t *testing.T) {
			if got := ps.Contains(tc.addr); got != tc.want {
				t.Errorf("Contains(%q) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}

	// Test invalid address/CIDR creation
	_, err = NewPrivateSubnet("8.8.8.8")
	if err == nil {
		t.Error("expected error creating PrivateSubnet with public IP")
	}

	_, err = NewPrivateSubnet("invalid")
	if err == nil {
		t.Error("expected error creating PrivateSubnet with invalid address")
	}
}
