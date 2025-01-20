// Copyright 2025 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package acmelego

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

func NewUser(email string, reg *registration.Resource, key crypto.PrivateKey) *User {
	return &User{email: email, key: key, reg: reg}
}

type User struct {
	email string
	reg   *registration.Resource
	key   crypto.PrivateKey
}

func (u User) GetEmail() string {
	return u.email
}
func (u User) GetRegistration() *registration.Resource {
	return u.reg
}

func (u User) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func NewPrivateKey() (crypto.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func NewConfig(user *User) *lego.Config {
	cfg := lego.NewConfig(user)
	return cfg
}
