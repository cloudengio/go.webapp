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
func (s Spec) String() string {
	return s.Role + "," + s.Method + "," + string(s.Resource) + "," + string(s.Action)
}

// Set represents a set of permissions, generally used to represent multiple
// permissions that have been granted.
type Set struct {
	Permissions []Spec
}

// Valid returns true if the Spec has all required fields.
func (s Spec) Valid() bool {
	return s.Role != "" && s.Method != "" && s.Resource != "" && s.Action != ""
}

// Satisfies returns true if at least one of the permissions in the Set
// satisfies the required Spec.
func (s Set) Satisfies(required Spec) bool {
	if !required.Valid() {
		return false
	}
	for _, permission := range s.Permissions {
		if permission.Role == required.Role &&
			permission.Method == required.Method &&
			Allowed(Pattern(permission.Action), Pattern(required.Action), ":") &&
			Allowed(Pattern(permission.Resource), Pattern(required.Resource), "/") {
			return true
		}
	}
	return false
}

// Specs provides an iterator over a permissions set.
func (s Set) Specs() iter.Seq[Spec] {
	return func(yield func(Spec) bool) {
		for _, permission := range s.Permissions {
			if !yield(permission) {
				return
			}
		}
	}
}
