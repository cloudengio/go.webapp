// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webhooks

import (
	"context"
	"testing"
)

func TestRouterFinishedNil(t *testing.T) {
	rt := newRouter(context.Background(), options{})
	defer rt.Stop(context.Background())
	if !rt.finished(nil) {
		t.Errorf("finished(nil): got false, want true")
	}
}
