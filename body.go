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

// ReadBodyLimit reads the request body with a size limit
// and returns it as a byte slice. If the body exceeds the limit
// ReadBodyLimit will return an http.MaxBytesError.
// If replace is true, the request body is replaced with a new reader
// that returns the same byte slice.
func ReadBodyLimit(r *http.Request, replace bool, limit int64) ([]byte, error) {
	r.Body = http.MaxBytesReader(nil, r.Body, limit)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return nil, err
		}
		return nil, fmt.Errorf("reading request body: %w", err)
	}
	if replace {
		r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	return body, nil
}
