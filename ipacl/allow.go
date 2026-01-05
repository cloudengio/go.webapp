// Copyright 2025 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package ipacl

import (
	"context"
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

// Contains returns whether the given IP address is allowed by the ACL.
func (a *ACL) Contains(ip netip.Addr) bool {
	return a.acl.Contains(ip)
}

// Option represents an option for NewACLHandler.
type Option func(o *options)

// AddressExtractor represents a function that extracts an IP address from an HTTP request.
type AddressExtractor func(r *http.Request) (string, netip.Addr, error)

type options struct {
	extractor         AddressExtractor
	deniedCounter     webapp.CounterInc
	notAllowedCounter webapp.CounterInc
	errorCounter      webapp.CounterInc
	label             string
}

// WithAddressExtractor returns an Option that sets the AddressExtractor.
func WithAddressExtractor(extractor AddressExtractor) Option {
	return func(o *options) {
		o.extractor = extractor
	}
}

// WithCounters returns an Option that sets three Counters:
// 1. one that is incremented when a request is denied because the
// IP address is in the deny ACL
// 2. one that is incremented if the address is not in the allow ACL
// 3. one that is incremented on error
func WithCounters(deniedCounter, notAllowedCounter, errorCounter webapp.CounterInc) Option {
	return func(o *options) {
		o.deniedCounter = deniedCounter
		o.notAllowedCounter = notAllowedCounter
		o.errorCounter = errorCounter
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

// Contains represents a function that returns whether the given IP address
// is in the ACL.
type Contains func(ip netip.Addr) bool

func noopCounter(context.Context) {}

// NewHandler creates a new http.Handler that enforces allow and deny ACLs.
// The deny ACL takes precedence over the allow ACL. If no ACLs are supplied
// then the handler allows all requests. If the remote IP cannot be
// determined or parsed then the request is denied.
// If the request's remote IP address is not allowed by the ACL,
// a 403 Forbidden response is returned, otherwise the request is
// passed to the given handler.
func NewHandler(handler http.Handler, allow, deny Contains, opts ...Option) http.Handler {
	if allow == nil {
		allow = func(netip.Addr) bool { return true }
	}
	if deny == nil {
		deny = func(netip.Addr) bool { return false }
	}
	ach := &aclHandler{
		allowed: allow,
		denied:  deny,
		handler: handler,
		opts: options{
			notAllowedCounter: noopCounter,
			deniedCounter:     noopCounter,
			errorCounter:      noopCounter,
		},
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
	allowed Contains
	denied  Contains
	handler http.Handler
}

// ServeHTTP implements the http.Handler interface.
func (h *aclHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientIP, ip, err := h.opts.extractor(r)
	if err != nil {
		h.opts.errorCounter(r.Context())
		http.Error(w, "forbidden", http.StatusForbidden)
		ctxlog.Debug(r.Context(), "failed to parse remote address", "remote_addr", clientIP, "error", err)
		return
	}
	forbidden := false
	if h.denied(ip) {
		forbidden = true
		h.opts.deniedCounter(r.Context())
	}
	if !forbidden && !h.allowed(ip) {
		forbidden = true
		h.opts.notAllowedCounter(r.Context())
	}
	if forbidden {
		http.Error(w, "forbidden", http.StatusForbidden)
		ctxlog.Debug(r.Context(), "ip address not allowed by acl", "ip", clientIP)
		return
	}
	h.handler.ServeHTTP(w, r)
}

// Config represents an IP address access control list configuration.
type Config struct {
	Addresses []string `yaml:"addresses" cmd:"list of ip addresses or cidr prefixes"`
	Direct    bool     `yaml:"direct" cmd:"set to true to use the requests.RemoteAddr"`   // Use the requests.RemoteAddr
	Proxy     bool     `yaml:"proxy" cmd:"set to true to use the X-Forwarded-For header"` // Use the X-Forwarded-For header
}

// NewACL creates a new ACL from the given configuration.
func (c Config) NewACL() (*ACL, error) {
	return NewACL(c.Addresses...)
}

// AddressExtractor returns an Option that sets the AddressExtractor.
func (c Config) AddressExtractor() (AddressExtractor, error) {
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
