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
	"cloudeng.io/net/netutil"
	"cloudeng.io/webapp"
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
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no addresses provided")
	}
	acl := &bart.Lite{}
	for _, addr := range addrs {
		p, err := netutil.ParseAddrOrPrefix(addr)
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
	counter   webapp.CounterInc
	label     string
}

// WithAddressExtractor returns an Option that sets the AddressExtractor.
func WithAddressExtractor(extractor AddressExtractor) Option {
	return func(o *options) {
		o.extractor = extractor
	}
}

// WithDeniedCounter returns an Option that sets the Counter that is
// incremented when a request is denied.
func WithDeniedCounter(counter webapp.CounterInc) Option {
	return func(o *options) {
		o.counter = counter
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

// NewHandler creates a new http.Handler that enforces the given ACL.
// If the request's remote IP address is not allowed by the ACL,
// a 403 Forbidden response is returned, otherwise the request is
// passed to the given handler.
func NewHandler(handler http.Handler, acl *ACL, opts ...Option) http.Handler {
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
		ctx := r.Context()
		ctxlog.Debug(ctx, "failed to parse remote address", "remote_addr", clientIP, "error", err)
		if h.opts.counter != nil {
			h.opts.counter(ctx)
		}
		return
	}
	if !h.acl.Allowed(ip) {
		ctx := r.Context()
		http.Error(w, "forbidden", http.StatusForbidden)
		ctxlog.Debug(ctx, "ip address not allowed by acl", "ip", clientIP)
		if h.opts.counter != nil {
			h.opts.counter(ctx)
		}
		return
	}
	h.handler.ServeHTTP(w, r)
}

// AllowConfig represents an IP address access control list configuration.
type AllowConfig struct {
	Addresses []string `yaml:"addresses" cmd:"list of ip addresses or cidr prefixes"`
	Direct    bool     `yaml:"direct" cmd:"set to true to use the requests.RemoteAddr"`   // Use the requests.RemoteAddr
	Proxy     bool     `yaml:"proxy" cmd:"set to true to use the X-Forwarded-For header"` // Use the X-Forwarded-For header
}

// NewACL creates a new ACL from the given configuration.
func (c AllowConfig) NewACL() (*ACL, error) {
	return NewACL(c.Addresses...)
}

// AddressExtractor returns an Option that sets the AddressExtractor.
func (c AllowConfig) AddressExtractor() (AddressExtractor, error) {
	if c.Direct && c.Proxy {
		return nil, fmt.Errorf("both direct and proxy are set")
	}
	if c.Direct {
		return RemoteAddrExtractor, nil
	}
	if c.Proxy {
		return XForwardedForExtractor, nil
	}
	return nil, fmt.Errorf("neither direct nor proxy is set")
}
