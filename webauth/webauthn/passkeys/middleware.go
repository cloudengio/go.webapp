// Copyright 2025 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package passkeys

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"cloudeng.io/logging/ctxlog"
	"cloudeng.io/webapp/cookies"
	"cloudeng.io/webapp/webauth/jwtutil"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// LoginManager defines the interface for managing logged in users who
// have authenticated using a passkey.
type LoginManager interface {
	// UserAuthenticated is called after a user has successfully logged in with a passkey.
	// It should be used to set a session Cookie, or a JWT token to be validated
	// on subsequent requests. The expiration parameter indicates how long the
	// login session should be valid.
	UserAuthenticated(r *http.Request, rw http.ResponseWriter, user UserID) error

	// AuthenticateUser is called to validate the user based on the request.
	// It should return the UserID of the authenticated user or an error if authentication fails.
	AuthenticateUser(r *http.Request) (UserID, error)
}

// JWTCookieLoginManager implements the LoginManager interface using JWTs stored in cookies.
type JWTCookieLoginManager struct {
	signer   jwtutil.Signer
	issuer   string
	audience []string

	loginCookie cookies.ScopeAndDuration
	// LoginCookie is set when the user has successfully logged in using
	// webauthn and is used to inform the server that the user has
	// successfully logged in
	LoginCookie cookies.Secure // initialized as cookies.T("webauthn_login")
}

// NewJWTCookieLoginManager creates a new JWTCookieLoginManager instance.
func NewJWTCookieLoginManager(signer jwtutil.Signer, issuer string, cookie cookies.ScopeAndDuration) JWTCookieLoginManager {
	m := JWTCookieLoginManager{
		signer:      signer,
		loginCookie: cookie.SetDefaults("", "/", 10*time.Minute),
		issuer:      issuer,
		audience:    []string{"webauthn"},
		LoginCookie: cookies.Secure("webauthn_login"),
	}
	return m
}

func (m JWTCookieLoginManager) UserAuthenticated(r *http.Request, rw http.ResponseWriter, user UserID) error {
	ctx := r.Context()
	now := time.Now()
	// Create the JWT claims.
	token, err := jwt.NewBuilder().
		Issuer(m.issuer).
		Audience(m.audience).
		Subject(user.String()).
		Expiration(now.Add(m.loginCookie.Duration)).
		NotBefore(now).
		Build()
	if err != nil {
		ctxlog.Error(ctx, "failed to create jwt token: %v", err)
		return fmt.Errorf("failed to create token: %v", err)
	}
	tokenString, err := m.signer.Sign(r.Context(), token)
	if err != nil {
		ctxlog.Error(ctx, "failed to sign jwt token: %v", err)
		return err
	}
	m.LoginCookie.Set(rw, m.loginCookie.Cookie(string(tokenString)))
	return nil
}

func (m JWTCookieLoginManager) AuthenticateUser(r *http.Request) (UserID, error) {
	tokenString, ok := m.LoginCookie.Read(r)
	if !ok {
		return nil, errors.New("missing authentication cookie")
	}
	token, err := m.signer.ParseAndValidate(r.Context(), []byte(tokenString),
		jwt.WithIssuer(m.issuer),
		jwt.WithAudience(m.audience[0]))
	if err != nil {
		return nil, err
	}
	subject, ok := token.Subject()
	if !ok {
		return nil, errors.New("missing subject")
	}
	uid, err := UserIDFromString(subject)
	if err != nil {
		return nil, err
	}
	return uid, nil
}
