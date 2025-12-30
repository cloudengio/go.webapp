// Copyright 2025 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package ipacl

import (
	"net/http"
	"net/netip"
	"strings"

	"cloudeng.io/logging/ctxlog"
	"github.com/gaissmai/bart"
)

// ACL represents an IP address access control list.
type ACL struct {
	acl *bart.Lite
}

// NewACL creates a new ACL from a list of IP addresses or CIDR prefixes.
// Each entry in the addrs slice can be either a single IP address or
// a CIDR prefix. If a single IP address is provided, it is treated
// as a /32 (for IPv4) or /128 (for IPv6) prefix.
func NewACL(addrs ...string) (*ACL, error) {
	acl := &bart.Lite{}
	for _, addr := range addrs {
		if !strings.Contains(addr, "/") {
			ip, err := netip.ParseAddr(addr)
			if err != nil {
				return nil, err
			}
			if ip.Is4() {
				addr = addr + "/32"
			} else {
				addr = addr + "/128"
			}
		}
		p, err := netip.ParsePrefix(addr)
		if err != nil {
			return nil, err
		}
		acl.Insert(p)
	}
	return &ACL{acl: acl}, nil
}

// Allowed returns whether the given IP address is allowed by the ACL.
func (a *ACL) Allowed(ip netip.Addr) bool {
	return a.acl.Contains(ip)
}

// NewACLHandler creates a new http.Handler that enforces the given ACL.
// If the request's remote IP address is not allowed by the ACL,
// a 403 Forbidden response is returned, otherwise the request is
// passed to the given handler.
func NewACLHandler(handler http.Handler, acl *ACL) http.Handler {
	return &aclHandler{
		acl:     acl,
		handler: handler,
	}
}

type aclHandler struct {
	acl     *ACL
	handler http.Handler
}

// ServeHTTP implements the http.Handler interface.
func (h *aclHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		ctxlog.Debug(r.Context(), "failed to parse remote address", "remote_addr", r.RemoteAddr, "error", err)
		return
	}
	if !h.acl.Allowed(ap.Addr()) {
		http.Error(w, "forbidden", http.StatusForbidden)
		ctxlog.Debug(r.Context(), "ip address not allowed by acl", "ip", ap.Addr().String())
		return
	}
	h.handler.ServeHTTP(w, r)
}
