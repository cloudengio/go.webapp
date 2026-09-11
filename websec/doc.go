// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

// Package websec provides HTTP security middleware for web applications.
// In particular, it offers NewLocalhostHandler to enforce security controls
// for HTTP/HTTPS endpoints bound to 127.0.0.1 or ::1, defending against
// non-loopback connections, DNS rebinding attacks, cross-site browser requests,
// and framing/MIME-sniffing vulnerabilities.
package websec
