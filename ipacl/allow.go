// Copyright 2025 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package ipacl

import (
	"fmt"
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
				addr += "/32"
			} else {
				addr += "/128"
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

// Option represents an option for NewACLHandler.
type Option func(o *options)

// AddressExtractor represents a function that extracts an IP address from an HTTP request.
type AddressExtractor func(r *http.Request) (string, netip.Addr, error)

type options struct {
	extractor AddressExtractor
}

// WithAddressExtractor returns an Option that sets the AddressExtractor.
func WithAddressExtractor(extractor AddressExtractor) Option {
	return func(o *options) {
		o.extractor = extractor
	}
}

func parseOptionalPort(addr string) (netip.Addr, error) {
	ap, err := netip.ParseAddrPort(addr)
	if err == nil {
		return ap.Addr(), nil
	}
	return netip.ParseAddr(addr)
}

// RemoteAddrExtractor returns the remote IP address from an HTTP request.
// It is the default AddressExtractor and is suitable
// for when a server is directly exposed to the internet.
func RemoteAddrExtractor(r *http.Request) (string, netip.Addr, error) {
	ip, err := parseOptionalPort(r.RemoteAddr)
	return r.RemoteAddr, ip, err
}

// XForwardedForExtractor returns the IP address from the X-Forwarded-For header.
// It uses the first IP address in the list.
func XForwardedForExtractor(r *http.Request) (string, netip.Addr, error) {
	xf := r.Header.Get("X-Forwarded-For")
	if xf == "" {
		return "", netip.Addr{}, fmt.Errorf("X-Forwarded-For header is empty")
	}
	// will always have at least one part, and we only
	// want the first ip address.
	parts := strings.Split(xf, ",")
	clientIP := strings.TrimSpace(parts[0])
	ap, err := parseOptionalPort(clientIP)
	return clientIP, ap, err
}

// NewACLHandler creates a new http.Handler that enforces the given ACL.
// If the request's remote IP address is not allowed by the ACL,
// a 403 Forbidden response is returned, otherwise the request is
// passed to the given handler.
func NewACLHandler(handler http.Handler, acl *ACL, opts ...Option) http.Handler {
	ach := &aclHandler{
		acl:     acl,
		handler: handler,
	}
	for _, opt := range opts {
		opt(&ach.opts)
	}
	if ach.opts.extractor == nil {
		ach.opts.extractor = RemoteAddrExtractor
	}
	return ach
}

type aclHandler struct {
	opts    options
	acl     *ACL
	handler http.Handler
}

// ServeHTTP implements the http.Handler interface.
func (h *aclHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientIP, ip, err := h.opts.extractor(r)
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		ctxlog.Debug(r.Context(), "failed to parse remote address", "remote_addr", clientIP, "error", err)
		return
	}
	if !h.acl.Allowed(ip) {
		http.Error(w, "forbidden", http.StatusForbidden)
		ctxlog.Debug(r.Context(), "ip address not allowed by acl", "ip", clientIP)
		return
	}
	h.handler.ServeHTTP(w, r)
}
