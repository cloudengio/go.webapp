// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webapp

import (
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"cloudeng.io/logging/ctxlog"
)

// HTTPServerError is an error that is returned by the HTTP server to the
// client and logged using ctxlog. The value of the error is used to
// identify the error in logs using the key 'error_src'.
// In addition, a random 64-bit integer is generated for each error and
// included in the response body and logs using the key 'error_id'.
type HTTPServerError string

var serverErrorSeed = time.Now().UnixNano()

var generator = rand.New(rand.NewSource(serverErrorSeed))

func formatErrorIDAndCode(eid int64, status int) string {
	return http.StatusText(status) + fmt.Sprintf(" (%02x)", eid)
}

// SendAndLog sends the error to the client and logs it using ctxlog.
func (e HTTPServerError) SendAndLog(w http.ResponseWriter, r *http.Request, status int, m string, args ...any) {
	eid := generator.Int63()
	http.Error(w, formatErrorIDAndCode(eid, status), status)
	ctxlog.Info(r.Context(), m, append([]any{
		"error_src", string(e),
		"error_id", eid,
		"path", r.URL.Path,
		"method", r.Method,
		"src", r.RemoteAddr,
	}, args...)...)
}

func (e HTTPServerError) Unauthorized(w http.ResponseWriter, r *http.Request, m string, args ...any) {
	e.SendAndLog(w, r, http.StatusUnauthorized, m, args...)
}

func (e HTTPServerError) Forbidden(w http.ResponseWriter, r *http.Request, m string, args ...any) {
	e.SendAndLog(w, r, http.StatusForbidden, m, args...)
}

func (e HTTPServerError) NotFound(w http.ResponseWriter, r *http.Request, m string, args ...any) {
	e.SendAndLog(w, r, http.StatusNotFound, m, args...)
}

func (e HTTPServerError) Internal(w http.ResponseWriter, r *http.Request, m string, args ...any) {
	e.SendAndLog(w, r, http.StatusInternalServerError, m, args...)
}

func (e HTTPServerError) BadRequest(w http.ResponseWriter, r *http.Request, m string, args ...any) {
	e.SendAndLog(w, r, http.StatusBadRequest, m, args...)
}
