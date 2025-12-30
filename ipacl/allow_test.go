// Copyright 2025 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package ipacl

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestACL(t *testing.T) {
	acl, err := NewACL("127.0.0.1", "192.168.1.0/24", "::1", "2001:db8::/32")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		ip      string
		allowed bool
	}{
		{"127.0.0.1", true},
		{"127.0.0.2", false},
		{"192.168.1.1", true},
		{"192.168.1.254", true},
		{"192.168.2.1", false},
		{"::1", true},
		{"::2", false},
		{"2001:db8::1", true},
		{"2001:db8:ffff::1", true},
		{"2001:db9::1", false},
	}

	for _, tc := range tests {
		ip, err := netip.ParseAddr(tc.ip)
		if err != nil {
			t.Errorf("failed to parse %v: %v", tc.ip, err)
			continue
		}
		if got, want := acl.Allowed(ip), tc.allowed; got != want {
			t.Errorf("Allowed(%v) = %v, want %v", tc.ip, got, want)
		}
	}
}

func TestACLSingleAddresses(t *testing.T) {
	tests := []struct {
		name     string
		aclAddrs []string
		checkIP  string
		allowed  bool
	}{
		{
			name:     "ipv4 single address",
			aclAddrs: []string{"1.2.3.4"},
			checkIP:  "1.2.3.4",
			allowed:  true,
		},
		{
			name:     "ipv4 single address mismatch",
			aclAddrs: []string{"1.2.3.4"},
			checkIP:  "1.2.3.5",
			allowed:  false,
		},
		{
			name:     "ipv6 single address",
			aclAddrs: []string{"2001:db8::1"},
			checkIP:  "2001:db8::1",
			allowed:  true,
		},
		{
			name:     "ipv6 single address mismatch",
			aclAddrs: []string{"2001:db8::1"},
			checkIP:  "2001:db8::2",
			allowed:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			acl, err := NewACL(tc.aclAddrs...)
			if err != nil {
				t.Fatalf("failed to create ACL: %v", err)
			}
			ip, err := netip.ParseAddr(tc.checkIP)
			if err != nil {
				t.Fatalf("failed to parse check IP %v: %v", tc.checkIP, err)
			}
			if got, want := acl.Allowed(ip), tc.allowed; got != want {
				t.Errorf("Allowed(%v) = %v, want %v", tc.checkIP, got, want)
			}
		})
	}
}

func TestACLInvalid(t *testing.T) {
	_, err := NewACL("invalid")
	if err == nil {
		t.Error("expected error for invalid address")
	}
	_, err = NewACL("1.2.3.4/33")
	if err == nil {
		t.Error("expected error for invalid prefix")
	}
}

func TestACLHandler(t *testing.T) {
	acl, err := NewACL("127.0.0.1", "192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := NewACLHandler(nextHandler, acl)

	tests := []struct {
		remoteAddr string
		wantStatus int
	}{
		{"127.0.0.1:1234", http.StatusOK},
		{"127.0.0.2:1234", http.StatusForbidden},
		{"192.168.1.50:80", http.StatusOK},
		{"192.168.2.50:80", http.StatusForbidden},
		{"invalid:80", http.StatusForbidden},
		{"1.2.3.4", http.StatusForbidden}, // Missing port
	}

	for _, tc := range tests {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = tc.remoteAddr
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if got, want := w.Code, tc.wantStatus; got != want {
			t.Errorf("ServeHTTP(%v) status = %v, want %v", tc.remoteAddr, got, want)
		}
	}
}
