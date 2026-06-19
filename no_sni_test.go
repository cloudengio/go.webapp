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

	matcher := func(addr string) bool {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		return host == "192.168.1.1" || host == "::1"
	}

	getConfig := func(_ *tls.ClientHelloInfo) (*tls.Config, error) { return tlsConfig, nil }

	callback := GetConfigForClientNoSNI(matcher, getConfig)

	// Case 1: nil ClientHelloInfo — return nil, nil
	cfg, err := callback(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Errorf("expected nil config for nil ClientHelloInfo, got %v", cfg)
	}

	// Case 2: ServerName is set — use default TLS config
	chi := &tls.ClientHelloInfo{
		ServerName: "example.com",
	}
	cfg, err = callback(chi)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Errorf("expected nil config when SNI is present, got %v", cfg)
	}

	// Case 3: no SNI, matched remote IP — return custom config
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
		t.Errorf("expected tlsConfig for matched address, got %v", cfg)
	}

	// Case 4: no SNI, unmatched remote IP — use default TLS config
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
		t.Errorf("expected nil config for unmatched address, got %v", cfg)
	}

	// Case 5: nil matcher — always returns nil, nil when no SNI
	callbackNoMatcher := GetConfigForClientNoSNI(nil, getConfig)
	cfg, err = callbackNoMatcher(chiPrivate)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Errorf("expected nil config with nil matcher, got %v", cfg)
	}
}
