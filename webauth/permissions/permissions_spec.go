// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package permissions

import (
	"strings"
)

var DefaultMaxComponentsAllowed = 10

// Spec represents a structured specification for authorization
// with support for wildcards (*).
// A spec is a colon separated list of components with well
// defined rules for determining if a request is allowed by a
// given requirement. Wildcards match entire spec components and
// cannot be used as partial matches. That is, a*b has no effect
// whereas a:* or a:*:b will, see the Allowed function for details.
type Spec string

// Allowed returns true if the request is allowed by the requirement.
// Both request and requirement must be non-empty, if either has more
// than DefaultMaxComponentsAllowed components, the function returns false.
// A trailing wildcard component ('<sep>*')in the request is allowed and will match
// any requirement that is more "specific", that is, has the request
// up and including the last <sep> before the '*' as a prefix.
// Using : as the separator, a:b:* is allowed by a:b:c, but not by a:b.
// Non-trailing wildcards match one and only one component. That is,
// a:*:c is allowed by a:b:c but not by a:b:c:d. Wildcards within
// components have no effect, that a:x*z:c will not be allowed by a:xyx:c.
func Allowed(request, requirement Spec, sep string) bool {
	if len(request) == 0 || len(requirement) == 0 {
		return false
	}
	requestNumComponents := strings.Count(string(request), sep) + 1
	requirementsNumComponents := strings.Count(string(requirement), sep) + 1
	if requestNumComponents > DefaultMaxComponentsAllowed || requirementsNumComponents > DefaultMaxComponentsAllowed {
		return false
	}

	// Handle common cases of exact match or trailing wildcard with
	// a simple prefix check first avoiding having to split the strings.
	if request == requirement {
		return true
	}
	wildcardEnd := strings.HasSuffix(string(request), sep+"*")
	if wildcardEnd {
		// request: a:b:*, matches requirement: a:b:c...
		if strings.HasPrefix(string(requirement), string(request[:len(request)-1])) {
			return true
		}
		// Trailing * should match longer requirements, but the prefix
		// match needs to allow for wildcards in the request.
	}

	if wildcardEnd {
		// The request cannot have more components than the requirement
		if requestNumComponents > requirementsNumComponents {
			return false
		}
	} else {
		// Otherwise the request and requirement must have the same number of components
		if requestNumComponents != requirementsNumComponents {
			return false
		}
	}

	requirementComponents := strings.Split(string(requirement), sep)
	requestComponents := strings.Split(string(request), sep)
	for i := range requestNumComponents {
		if requestComponents[i] == "*" {
			continue
		}
		if requestComponents[i] != requirementComponents[i] {
			return false
		}
	}
	return true
}
