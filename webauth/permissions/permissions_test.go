// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package permissions_test

import (
	"slices"
	"testing"

	"cloudeng.io/webapp/webauth/permissions"
	"cloudeng.io/webapp/webauth/permissions/permissionstestutil"
)

func TestPermissions_Satisfies(t *testing.T) {
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
			req := permissions.Spec{
				Role:     tt.role,
				Method:   tt.method,
				Resource: permissions.Resource(tt.resource),
				Action:   permissions.Action(tt.action),
			}
			got := tt.perms.Satisfies(req)
			if got, want := got, tt.want; got != want {
				t.Errorf("%v: %v.Satisfies(%v) = %v, want %v", tt.name, tt.perms, req, got, want)
			}
		})
	}
}

func TestSet_Specs(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		var s permissions.Set
		got := slices.Collect(s.Specs())
		if len(got) != 0 {
			t.Errorf("got %v, want empty", got)
		}
	})

	t.Run("Single", func(t *testing.T) {
		s := permissionstestutil.NewMust("user", "GET", "/res", "read")
		got := slices.Collect(s.Specs())
		if len(got) != 1 {
			t.Fatalf("got %d specs, want 1", len(got))
		}
		if got[0] != s.Permissions[0] {
			t.Errorf("got %v, want %v", got[0], s.Permissions[0])
		}
	})

	t.Run("Multiple", func(t *testing.T) {
		s := permissionstestutil.NewMust("user", "GET", "/res", "read", "admin", "POST", "/res", "write")
		got := slices.Collect(s.Specs())
		if len(got) != 2 {
			t.Fatalf("got %d specs, want 2", len(got))
		}
		for i, spec := range got {
			if spec != s.Permissions[i] {
				t.Errorf("[%d]: got %v, want %v", i, spec, s.Permissions[i])
			}
		}
	})

	t.Run("EarlyStop", func(t *testing.T) {
		s := permissionstestutil.NewMust("user", "GET", "/res", "read", "admin", "POST", "/res", "write")
		var count int
		for range s.Specs() {
			count++
			break
		}
		if count != 1 {
			t.Errorf("got %d iterations, want 1", count)
		}
	})
}
