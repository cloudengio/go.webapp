// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package permissions

import (
	"fmt"
	"testing"
)

func TestAllowed(t *testing.T) {
	tests := []struct {
		request     Spec
		requirement Spec
		allowed     bool
	}{
		// Exact matches
		{"a:b", "a:b", true},
		{"a:b:c", "a:b:c", true},
		{"a:b:c:", "a:b:c:", true},

		{"", "", false},    // len 0 check
		{"a:b", "", false}, // len 0 check
		{"", "a:b", false}, // len 0 check

		// Trailing wildcard in request
		// Comment says: a:b:* is allowed by a:b:c
		{"a:b:*", "a:b:c", true},
		{"a:b:*", "a:b:c:d", true},
		// a:b:* matches a prefix of "a:b:" so "a:b" is NOT allowed
		{"a:b:*", "a:b", false},
		// "a:bc" does not have prefix "a:b:"
		{"a:b:*", "a:bc", false},

		// Trailing wildcard NOT matching
		{"a:b:*", "x:y:z", false},
		{"a:b:*", "a:c:d", false},

		// Non-trailing wildcard
		{"a:*:c", "a:b:c", true},
		{"a:*:c", "a:z:c", true},
		{"a:*:c", "a:b:d", false},   // mismatch last component
		{"a:*:c", "a:b:c:d", false}, // length mismatch

		// Wildcard in requirement (treated as literal)
		{"a:b", "a:*", false},
		{"a:*", "a:*", true}, // exact match

		// Edge cases
		{":*", "anything", false}, // stripped=":", prefix of "anything" is NOT ":"
		{"*", "anything", true},   // Single component wildcard matches single component requirement

		// Longer request
		{"a:b:c:d", "a:b:c", false}, // The request should include a wilcard
		// Longer requirement
		{"a:b:c", "a:b:c:d", false}, // The requirement should include a wilcard

		// Empty componets in request or requirement
		{"a:b:c:", "a:b:c", false},
		{"a:b:c", "a:b:c:", false},

		// Multiple wildcards
		// 1. Trailing * fails to match as a prefix but matches as individual components
		{"*:*:*", "a:b:c", true},
		{"*:b:*", "a:b:c", true},
		{"a:b:*", "a:b:c", true},
		{"*:b:c", "a:b:c", true},

		// 2. Trailing * should match longer requirements
		{"*:*:*", "a:b:c:d", true},

		{"*:*:*", "a:b", false}, // Trailing * stripped to "*:*:", mismatch

		// Complex
		{"a:*:*:d", "a:b:c:d", true},
		{"a:*:*:d", "a:b:c:e", false},

		// Case sensitivity
		{"A:b", "a:b", false},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_%s", tt.request, tt.requirement), func(t *testing.T) {
			if got := Allowed(tt.request, tt.requirement, ":"); got != tt.allowed {
				t.Errorf("Allowed(%q, %q) = %v, want %v", tt.request, tt.requirement, got, tt.allowed)
			}
		})
	}
}
