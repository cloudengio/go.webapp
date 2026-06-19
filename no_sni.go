// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webapp

import (
	"crypto/tls"
)

// GetConfigForClientNoSNI returns a function that can be used as the
// GetConfigForClient callback in a tls.Config to allow connections from
// addresses that match the provided matcher function that do not include an
// SNI (Server Name Indication) in the TLS handshake. This is primarily intended
// for use with load balancer health checks etc.
func GetConfigForClientNoSNI(matcher func(addr string) bool, getConfig func(*tls.ClientHelloInfo) (*tls.Config, error)) func(*tls.ClientHelloInfo) (*tls.Config, error) {
	if matcher == nil {
		matcher = func(string) bool { return false }
	}
	return func(clientHello *tls.ClientHelloInfo) (*tls.Config, error) {
		if clientHello == nil || clientHello.Conn == nil || clientHello.ServerName != "" {
			return nil, nil // Use default TLS config for clients that provide SNI or if clientHello is nil
		}
		clientRemoteAddr := clientHello.Conn.RemoteAddr().String()
		if matcher(clientRemoteAddr) {
			return getConfig(clientHello)
		}
		return nil, nil // Use default TLS config for non-private clients
	}
}
