// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package permissionstestutil

import (
	"fmt"

	"cloudeng.io/webapp/webauth/permissions"
)

// New creates a new Permissions instance from a list of
// role-method-resource-action 4-tuples.
func New(roleMethodResourceAction4Tuples ...string) (permissions.Set, error) {
	if len(roleMethodResourceAction4Tuples)%4 != 0 {
		return permissions.Set{}, fmt.Errorf("expected a multiple of 4 strings for role-method-resource-action 4-tuples")
	}
	perms := permissions.Set{}
	for i := 0; i < len(roleMethodResourceAction4Tuples); i += 4 {
		perms.Permissions = append(perms.Permissions, permissions.Grant{
			Role:     roleMethodResourceAction4Tuples[i],
			Method:   roleMethodResourceAction4Tuples[i+1],
			Resource: permissions.Resource(roleMethodResourceAction4Tuples[i+2]),
			Action:   permissions.Action(roleMethodResourceAction4Tuples[i+3]),
		})
	}
	return perms, nil
}

// NewMust is like New but panics on error.
func NewMust(roleMethodResourceAction4Tuples ...string) permissions.Set {
	perms, err := New(roleMethodResourceAction4Tuples...)
	if err != nil {
		panic(err)
	}
	return perms
}
