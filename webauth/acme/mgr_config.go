// Copyright 2021 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

// Package acme provides support for working with ACNE service providers
// such as letsencrypt.org.
package acme

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"slices"
	"time"

	"cloudeng.io/webapp"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

const (
	// LetsEncryptStaging is the URL for the letsencrypt.org staging service
	// and is used as the default by this package.
	LetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"
	// LetsEncryptProduction is the URL for the letsencrypt.org production service.
	LetsEncryptProduction = acme.LetsEncryptURL
)

// ServiceFlags represents the flags required to configure an ACME client
// instance for managing TLS certificates for hosts/domains using the
// acme http-01 challenge. Note that wildcard domains are not supported
// by this challenge.
// The currently supported/tested acme service providers are letsencrypt
// staging and production via the values 'letsencrypt-staging' and
// 'letsencrypt' for the --acme-service flag; however any URL can be specified
// via this flag, in particular to use pebble for testing set this to the URL
// of the local pebble instance and also set the --acme-testing-ca
// flag to point to the pebble CA certificate pem file.
type ServiceFlags struct {
	Provider    string        `subcmd:"acme-service,letsencrypt-staging,'the acme service to use, specify letsencrypt or letsencrypt-staging or a url'"`
	RenewBefore time.Duration `subcmd:"acme-renew-before,720h,how early certificates should be renewed before they expire."`
	Email       string        `subcmd:"acme-email,,email to contact for information on the domain"`
	UserAgent   string        `subcmd:"acme-user-agent,cloudeng.io/webapp/webauth/acme,'user agent to use when connecting to the acme service'"`
}

// AutocertConfig converts the flag values to a AutocertConfig instance.
func (f ServiceFlags) AutocertConfig() AutocertConfig {
	return AutocertConfig{
		Provider:    f.Provider,
		RenewBefore: f.RenewBefore,
		Email:       f.Email,
		UserAgent:   f.UserAgent,
	}
}

// AutocertConfig represents the configuration required to create an
// autocert.Manager.
type AutocertConfig struct {
	// Contact email for the ACME account, note, changing this may create
	// a new account with the ACME provider. The key associated with an account
	// is required for revoking certificates issued using that account.
	Email       string        `yaml:"email"`
	UserAgent   string        `yaml:"user_agent"`    // User agent to use when connecting to the ACME service.
	Provider    string        `yaml:"acme_provider"` // ACME service provider URL or 'letsencrypt' or 'letsencrypt-staging'.
	RenewBefore time.Duration `yaml:"renew_before"`  // How early certificates should be renewed before they expire.

	AllowRSACertificates bool `yaml:"allow_rsa_certificates" doc:"if true, allow RSA certificates to be issued, otherwise only ECDSA certificates will be issued"`
}

func (ac AutocertConfig) DirectoryURL() string {
	switch ac.Provider {
	case "letsencrypt":
		return LetsEncryptProduction
	case "letsencrypt-staging":
		return LetsEncryptStaging
	default:
		if len(ac.Provider) == 0 {
			return LetsEncryptStaging
		}
		return ac.Provider
	}
}

// Manager embeds an autocert.Manager but overrides the GetCertificate function
// to enforce the AllowRSACertificates setting.
type Manager struct {
	*autocert.Manager
	allowRSA bool
}

func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if m.allowRSA {
		return m.Manager.GetCertificate(hello)
	}
	if hello != nil && !SupportsECDSA(hello) {
		return nil, fmt.Errorf("hello for %s from %s does not support ECDSA certificates", hello.ServerName, webapp.RemoteAddrFromClientHello(hello))
	}
	return m.Manager.GetCertificate(hello)
}

// TLSConfig returns a tls.Config obtained using from the underlying autocert.Manager,
// but with the GetCertificate function replaced with the Manager's GetCertificate
// function, which enforces the AllowRSACertificates setting.
func (m *Manager) TLSConfig() *tls.Config {
	cfg := m.Manager.TLSConfig()
	cfg.GetCertificate = m.GetCertificate
	return cfg
}

// NewAutocertManager creates a new autocert.Manager from the supplied config.
// Any supplied hosts specify the allowed hosts for the manager, ie. those
// for which it will obtain/renew certificates.
func NewAutocertManager(cache autocert.Cache, cl AutocertConfig, allowedHosts ...string) (*Manager, error) {
	if cache == nil {
		return nil, fmt.Errorf("no cache provided")
	}
	hostPolicy := autocert.HostWhitelist(allowedHosts...)

	provider := cl.Provider
	switch provider {
	case "letsencrypt":
		provider = LetsEncryptProduction
	case "letsencrypt-staging":
		provider = LetsEncryptStaging
	default:
		if len(provider) == 0 {
			provider = LetsEncryptStaging
		} else if _, err := url.Parse(provider); err != nil {
			return nil, fmt.Errorf("invalid url: %v: %v", provider, err)
		}
	}
	client := &acme.Client{
		DirectoryURL: provider,
		UserAgent:    cl.UserAgent,
	}
	mgr := &autocert.Manager{
		Prompt:      acme.AcceptTOS,
		Cache:       cache,
		Client:      client,
		Email:       cl.Email,
		HostPolicy:  hostPolicy,
		RenewBefore: cl.RenewBefore,
	}
	return &Manager{Manager: mgr, allowRSA: cl.AllowRSACertificates}, nil
}

// GetCertificateECDSAOnly returns a GetCertificate function that wraps the
// provided autocert.Manager's GetCertificate function with a check that the client
// supports ECDSA certificates, returning an error if not.
func GetCertificateECDSAOnly(getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello != nil && !SupportsECDSA(hello) {
			return nil, fmt.Errorf("hello for %s from %s does not support ECDSA certificates", hello.ServerName, webapp.RemoteAddrFromClientHello(hello))
		}
		return getCert(hello)
	}
}

// SupportsECDSA returns true if the client requests supports ECDSA certificates
// Taken from acme/autocert.go
func SupportsECDSA(hello *tls.ClientHelloInfo) bool {
	if hello == nil {
		return false
	}
	if hello.SignatureSchemes != nil {
		ecdsaOK := false
	schemeLoop:
		for _, scheme := range hello.SignatureSchemes {
			const tlsECDSAWithSHA1 tls.SignatureScheme = 0x0203 // constant added in Go 1.10
			switch scheme {
			case tlsECDSAWithSHA1, tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384, tls.ECDSAWithP521AndSHA512:
				ecdsaOK = true
				break schemeLoop
			}
		}
		if !ecdsaOK {
			return false
		}
	}
	if hello.SupportedCurves != nil {
		if !slices.Contains(hello.SupportedCurves, tls.CurveP256) {
			return false
		}
	}
	for _, suite := range hello.CipherSuites {
		switch suite {
		case tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:
			return true
		}
	}
	return false
}
