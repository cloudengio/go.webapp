// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webapp

import (
	"crypto/tls"
	"net"
	"testing"
)

type mockAddr struct {
	addr string
}

func (m mockAddr) Network() string { return "tcp" }
func (m mockAddr) String() string  { return m.addr }

type mockConn struct {
	net.Conn
	remote mockAddr
}

func (m mockConn) RemoteAddr() net.Addr { return m.remote }

func TestGetConfigForClientNoSNI(t *testing.T) {
	tlsConfig := &tls.Config{}

	// Create matcher function
	matcher := func(addr string) bool {
		// Just a simple matcher that matches a specific IP for testing
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		return host == "192.168.1.1" || host == "::1"
	}

	callback := GetConfigForClientNoSNI(matcher, tlsConfig)

	// Case 1: ServerName is NOT empty (should return nil, nil)
	chi := &tls.ClientHelloInfo{
		ServerName: "example.com",
	}
	cfg, err := callback(chi)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Errorf("expected nil config, got %v", cfg)
	}

	// Case 2: ServerName is empty, remote IP is matched
	chiPrivate := &tls.ClientHelloInfo{
		ServerName: "",
		Conn: mockConn{
			remote: mockAddr{addr: "192.168.1.1:1234"},
		},
	}
	cfg, err = callback(chiPrivate)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != tlsConfig {
		t.Errorf("expected tlsConfig, got %v", cfg)
	}

	// Case 3: ServerName is empty, remote IP is not matched
	chiPublic := &tls.ClientHelloInfo{
		ServerName: "",
		Conn: mockConn{
			remote: mockAddr{addr: "8.8.8.8:1234"},
		},
	}
	cfg, err = callback(chiPublic)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Errorf("expected nil config, got %v", cfg)
	}
}
