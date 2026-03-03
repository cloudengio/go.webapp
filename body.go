// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webapp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// ErrBodyTooLarge is returned when the request body exceeds the limit.
var ErrBodyTooLarge = errors.New("request body exceeds limit")

// ReadBodyLimit reads the request body with a size limit
// and returns it as a byte slice. If the body exceeds the limit,
// an error is returned.
// If replace is true, the request body is replaced with a new reader
// that returns the same byte slice.
func ReadBodyLimit(r *http.Request, replace bool, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("reading request body: %w", err)
	}
	if int64(len(body)) > limit {
		return nil, ErrBodyTooLarge
	}
	if replace {
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	return body, nil
}
