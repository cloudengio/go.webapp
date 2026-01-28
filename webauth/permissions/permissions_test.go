// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package permissions_test

import (
	"testing"

	"cloudeng.io/webapp/webauth/permissions"
	"cloudeng.io/webapp/webauth/permissions/permissionstestutil"
)

func TestPermissions_AllowedFor(t *testing.T) {
	tests := []struct {
		name     string
		perms    permissions.Set
		role     string
		resource string
		method   string
		action   string
		want     bool
	}{
		{
			name:     "Exact Match",
			perms:    permissionstestutil.NewMust("admin", "GET", "res1", "read"),
			role:     "admin",
			action:   "read",
			resource: "res1",
			method:   "GET",
			want:     true,
		},
		{
			name:     "Role Mismatch",
			perms:    permissionstestutil.NewMust("admin", "GET", "res1", "read"),
			role:     "user",
			action:   "read",
			resource: "res1",
			method:   "GET",
			want:     false,
		},
		{
			name:     "Action Mismatch",
			perms:    permissionstestutil.NewMust("admin", "GET", "res1", "read"),
			role:     "admin",
			action:   "write",
			resource: "res1",
			method:   "GET",
			want:     false,
		},
		{
			name:     "Resource Mismatch",
			perms:    permissionstestutil.NewMust("admin", "GET", "res1", "read"),
			role:     "admin",
			action:   "read",
			resource: "res2",
			method:   "GET",
			want:     false,
		},
		{
			name:     "Wildcard Action",
			perms:    permissionstestutil.NewMust("admin", "POST", "res1", "*"),
			role:     "admin",
			action:   "write",
			resource: "res1",
			method:   "POST",
			want:     true,
		},
		{
			name:     "Wildcard Resource",
			perms:    permissionstestutil.NewMust("admin", "GET", "res/*", "read"),
			role:     "admin",
			action:   "read",
			resource: "res/1",
			method:   "GET",
			want:     true,
		},
		{
			name:     "Multiple Permissions - First Match",
			perms:    permissionstestutil.NewMust("admin", "GET", "res1", "read", "user", "PUT", "res2", "write"),
			role:     "admin",
			action:   "read",
			resource: "res1",
			method:   "GET",
			want:     true,
		},
		{
			name:     "Multiple Permissions - Second Match",
			perms:    permissionstestutil.NewMust("user", "GET", "res1", "read", "admin", "PUT", "res2", "write"),
			role:     "admin",
			action:   "write",
			resource: "res2",
			method:   "PUT",
			want:     true,
		},
		{
			name:     "Multiple Permissions - No Match",
			perms:    permissionstestutil.NewMust("admin", "GET", "res1", "read", "user", "PUT", "res2", "write"),
			role:     "admin",
			action:   "delete",
			resource: "res3",
			method:   "DELETE",
			want:     false,
		},
		{
			name:     "Empty Permissions",
			perms:    permissionstestutil.NewMust("admin", "", "", ""),
			role:     "admin",
			action:   "delete",
			resource: "res3",
			method:   "DELETE",
			want:     false,
		},
		{
			name:     "Empty Permissions",
			perms:    permissionstestutil.NewMust("admin", "", "", ""),
			role:     "admin",
			action:   "read",
			resource: "res1",
			method:   "GET",
			want:     false,
		},
		{
			name:     "Wildcard All",
			perms:    permissionstestutil.NewMust("superuser", "GET", "/*", "*"),
			role:     "superuser",
			action:   "any_action",
			resource: "/any/resource",
			method:   "GET",
			want:     true,
		},
		{
			name:     "Wildcard All - Correct",
			perms:    permissionstestutil.NewMust("superuser", "GET", "/*", "*"),
			role:     "superuser",
			action:   "any_action",
			resource: "/any/resource",
			method:   "GET",
			want:     true,
		},
		{
			name:     "Resource with Hierarchy",
			perms:    permissionstestutil.NewMust("user", "GET", "items/*", "read"),
			role:     "user",
			action:   "read",
			resource: "items/123",
			method:   "GET",
			want:     true,
		},
		{
			name:     "Method Match - Explicit",
			perms:    permissionstestutil.NewMust("user", "POST", "res1", "create"),
			role:     "user",
			action:   "create",
			resource: "res1",
			method:   "POST",
			want:     true,
		},
		{
			name:     "Method Mismatch",
			perms:    permissionstestutil.NewMust("user", "POST", "res1", "create"),
			role:     "user",
			action:   "create",
			resource: "res1",
			method:   "GET",
			want:     false,
		},
		{
			name:     "Method Empty in Perm (Should Fail)",
			perms:    permissionstestutil.NewMust("user", "", "res1", "read"),
			role:     "user",
			action:   "read",
			resource: "res1",
			method:   "GET",
			want:     false,
		},
		{
			name:     "Method Empty in Request (Should Fail)",
			perms:    permissionstestutil.NewMust("user", "GET", "res1", "read"),
			role:     "user",
			action:   "read",
			resource: "res1",
			method:   "",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.perms.AllowedFor(tt.role, tt.method, tt.resource, tt.action)
			if got, want := got, tt.want; got != want {
				t.Errorf("%v: %v.AllowedFor(Role: %v, Method: %v, Resource: %v, Action: %v) = %v, want %v", tt.name, tt.perms, tt.role, tt.method, tt.resource, tt.action, got, want)
			}
		})
	}
}
