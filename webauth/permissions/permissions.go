// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package permissions

// Resource refers to the resource on which the action is performed.
// For resources, / is used as a separator between components.
// By convention, resources are URI paths.
type Resource Spec

// Action refers to the action to perform on the resource.
// For actions, colons are used as a separator between components.
type Action Spec

// Grant represents the ability to perform some action on a resource.
type Grant struct {
	Role     string   // The role of the user performing the action
	Method   string   // Method to perform on the resource
	Resource Resource // The resource on which the action is performed
	Action   Action   // The action to perform on the resource
}

// String returns a string representation of the Grant.
func (g Grant) String() string {
	return g.Role + "," + g.Method + "," + string(g.Resource) + "," + string(g.Action)
}

// Set represents a set of permissions.
type Set struct {
	Permissions []Grant
}

// AllowedFor returns true if at least one of the permissions granted is
// allowed for the requested role, method, action and resource.
func (p Set) AllowedFor(role, method, resource, action string) bool {
	if role == "" || method == "" || resource == "" || action == "" {
		return false
	}
	for _, permission := range p.Permissions {
		if permission.Role == role &&
			permission.Method == method &&
			Allowed(Spec(permission.Action), Spec(action), ":") &&
			Allowed(Spec(permission.Resource), Spec(resource), "/") {
			return true
		}
	}
	return false
}
