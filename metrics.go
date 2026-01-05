// Copyright 2025 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webapp

import "context"

// CounterInc is a function that increments a counter metric.
type CounterInc func(ctx context.Context)

// CounterAdd is a function that adds a delta to a counter metric.
type CounterAdd func(ctx context.Context, delta float64)

// CounterVecInc is a function that increments a counter metric with the given labels.
type CounterVecInc func(ctx context.Context, labels ...string)

// CounterVecAdd is a function that adds a delta to a counter metric with the given labels.
type CounterVecAdd func(ctx context.Context, delta float64, labels ...string)

// Observe is a function that records a value for an observer metric.
type Observe func(ctx context.Context, value float64)
