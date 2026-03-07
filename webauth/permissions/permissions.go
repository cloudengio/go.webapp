// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package permissions

import "iter"

// Resource refers to the resource on which the action is performed.
// For resources, / is used as a separator between components.
// By convention, resources are URI paths.
type Resource Pattern

// Action refers to the action to perform on the resource.
// For actions, colons are used as a separator between components.
type Action Pattern

// Spec represents the ability to perform some action on a resource.
type Spec struct {
	Role     string   `json:"role"`     // The role of the user performing the action
	Method   string   `json:"method"`   // Method to perform on the resource
	Resource Resource `json:"resource"` // The resource on which the action is performed
	Action   Action   `json:"action"`   // The action to perform on the resource
}

// String returns a string representation of the Spec.
func (g Spec) String() string {
	return g.Role + "," + g.Method + "," + string(g.Resource) + "," + string(g.Action)
}

// Set represents a set of permissions.
type Set struct {
	Permissions []Spec
}

// Valid returns true if the Request has all required fields.
func (r Spec) Valid() bool {
	return r.Role != "" && r.Method != "" && r.Resource != "" && r.Action != ""
}

// AllowedFor returns true if at least one of the permissions granted is
// allowed for the requested role, method, action and resource.
func (p Set) AllowedFor(request Spec) bool {
	if !request.Valid() {
		return false
	}
	for _, permission := range p.Permissions {
		if permission.Role == request.Role &&
			permission.Method == request.Method &&
			Allowed(Pattern(permission.Action), Pattern(request.Action), ":") &&
			Allowed(Pattern(permission.Resource), Pattern(request.Resource), "/") {
			return true
		}
	}
	return false
}

// Specs provides an iterator over a permissions set.
func (p Set) Specs() iter.Seq[Spec] {
	return func(yield func(Spec) bool) {
		for _, permission := range p.Permissions {
			if !yield(permission) {
				return
			}
		}
	}
}
