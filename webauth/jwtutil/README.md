# Package [cloudeng.io/webapp/webauth/jwtutil](https://pkg.go.dev/cloudeng.io/webapp/webauth/jwtutil?tab=doc)

```go
import cloudeng.io/webapp/webauth/jwtutil
```

Package jwtutil provides support for creating and verifying JSON Web Tokens
(JWTs) managed by the github.com/lestrrat-go/jwx/v3/jwk package. This
package provides simplified wrappers around the JWT signing and verification
process to allow for more convenient usage in web applications.

## Constants
### DefaultVerificationURLValidity
```go
DefaultVerificationURLValidity = 5 * time.Minute

```



## Variables
### ErrNoKeyStore, ErrKeyNotFound
```go
// ErrNoKeyStore is returned when the context supplied to one of the
// functions in this package does not contain a keys.InMemoryKeyStore.
ErrNoKeyStore = errors.New("no key store in context")
// ErrKeyNotFound is returned when a named key is not present in the key
// store obtained from the context.
ErrKeyNotFound = errors.New("key not found")

```

### ErrNoCookie
```go
ErrNoCookie = errors.New("no such cookie")

```
ErrNoCookie is returned when a request does not carry the cookie named by a
JWTCookieValidatorConfig.

### ErrReservedClaim
```go
ErrReservedClaim = errors.New("reserved claim")

```
ErrReservedClaim is returned when a caller attempts to set a reserved JWT
claim.



## Functions
### Func CloneKeyInfoForPublicKey
```go
func CloneKeyInfoForPublicKey(info keys.Info) keys.Info
```
CloneKeyInfoForPublicKey returns a copy of the key info without the private
key material, suitable for use as a public key.

### Func ContextWithToken
```go
func ContextWithToken(ctx context.Context, key string, tok jwt.Token) context.Context
```
ContextWithToken returns a new context derived from ctx that carries
the provided jwt.Token keyed by key. If ctx already contains tokens,
the existing tokens are preserved and the token for key is added or updated.

### Func CreateVerificationToken
```go
func CreateVerificationToken(ctx context.Context, s Signer, subject, claimKey string, claimValue any, expiresIn time.Duration, issuer, audience string) ([]byte, error)
```
CreateVerificationToken creates a compact JWT containing the specified claim
to be verified along with an expiration time, subject, issuer, and audience.

### Func JWTIssuer
```go
func JWTIssuer(signer Signer, opts ...JWTIssuerOption) (http.Handler, error)
```
JWTIssuer returns an http.Handler that issues JWTs using signer according
to the configured options. It runs without authentication, issuing tokens to
any client that accesses it.

### Func JWTIssuerMust
```go
func JWTIssuerMust(signer Signer, opts ...JWTIssuerOption) http.Handler
```
JWTIssuerMust creates a new JWTIssuer handler or panics on error.

### Func KeySetForKeys
```go
func KeySetForKeys(ctx context.Context, keys ...keys.Info) (jwk.Set, error)
```
KeySetForKeys returns a jwk.KeySet containing the public halves of the keys
provided.

### Func NewED25519KeyInfo
```go
func NewED25519KeyInfo(user, id string) (keys.Info, error)
```
NewED25519KeyInfo generates an ed25519 key pair and returns it as a
keys.Info that can be added to a key store, or written to a keychain item,
and used as a JWT signing key, as well as the public key for use as a
verification key. The private key is stored as the key's token with the
algorithm and public key in its extra information, as described by KeyExtra.

### Func NewJWTIssuer
```go
func NewJWTIssuer(signer Signer, opts ...JWTIssuerOption) (http.Handler, error)
```
NewJWTIssuer creates a new http.Handler that issues JWTs using signer
according to the configured options. It returns an error if signer is nil,
if more than one cookie option is specified, or if any custom claims match
reserved standard JWT claims (iss, sub, aud, exp, nbf, iat, jti).

### Func NewJWTIssuerMust
```go
func NewJWTIssuerMust(signer Signer, opts ...JWTIssuerOption) http.Handler
```
NewJWTIssuerMust creates a new http.Handler that issues JWTs using signer,
and panics if an error occurs.

### Func PublicKeyFromKeyInfo
```go
func PublicKeyFromKeyInfo(ctx context.Context, info keys.Info) (jwk.Key, error)
```
PublicKeyFromKeyInfo returns the public key corresponding to the key
material in info, using the JWKKey implementation registered for the
algorithm named in its extra information. The returned key carries the
algorithm and usage required to verify a token signed by the corresponding
Signer, but not a key id: that depends on how the key is being looked up and
is the caller's responsibility to set, see keySetForKeys.

### Func TokenFromContext
```go
func TokenFromContext(ctx context.Context, key string) (jwt.Token, bool)
```
TokenFromContext retrieves the jwt.Token keyed by key from ctx, if present.

### Func TokensFromContext
```go
func TokensFromContext(ctx context.Context) map[string]jwt.Token
```
TokensFromContext returns a copy of all jwt.Token instances stored in ctx,
keyed by their string identifiers.

### Func ValidateVerificationToken
```go
func ValidateVerificationToken(ctx context.Context, v Validator, tokenString string, expectedSubject, expectedIssuer, expectedAudience, claimKey string, claimValue any) error
```
ValidateVerificationToken parses the token via the provided Validator,
performs standard JWT claim checks (Issuer, Audience, Expiration), and
extracts the specified claim from the validated JWT structure.

### Func VerificationURL
```go
func VerificationURL(baseURL string, tokenBytes []byte) (string, error)
```
VerificationURL generates a verification URL by appending the signed
verification token as a query parameter ("token") to the provided baseURL.
The URL will encode any existing query parameters gracefully. A URL so
generated should and its token should have a very short expiration time and
ideally be used only once.



## Types
### Type CookieSigner
```go
type CookieSigner struct {
	Signer
	// contains filtered or unexported fields
}
```
CookieSigner issues JWTs carried in a named cookie as specified by a
JWTCookieSignerConfig. It only signs; a service that also needs to verify
the cookies it issues should build a separate CookieVerifier from the
matching JWTCookieValidatorConfig (see VerifierConfig).

### Methods

```go
func (cs *CookieSigner) Cookie(ctx context.Context, token jwt.Token) (*http.Cookie, error)
```
Cookie signs token and returns a cookie containing it that is scoped and
expires as specified by the configuration.


```go
func (cs *CookieSigner) Issue(ctx context.Context, rw http.ResponseWriter, subject string, claims map[string]any) error
```
Issue creates, signs and sets a cookie containing a token for subject and
claims as per NewToken and SetCookie.


```go
func (cs *CookieSigner) Name() string
```
Name returns the name of the cookie that tokens are issued in.


```go
func (cs *CookieSigner) NewToken(subject string, claims map[string]any) (jwt.Token, error)
```
NewToken returns a token for subject with the issuer, audience,
subject, claims and duration specified by the configuration (see
JWTSignerConfig.Builder), along with any additional claims supplied here.
subject and claims, if not empty, override the configured ones. If claims
contains any reserved standard JWT claims (iss, sub, aud, exp, nbf, iat,
jti), ErrReservedClaim is returned.


```go
func (cs *CookieSigner) SetCookie(ctx context.Context, rw http.ResponseWriter, token jwt.Token) error
```
SetCookie signs token and sets the resulting cookie on rw.




### Type CookieVerifier
```go
type CookieVerifier struct {
	// contains filtered or unexported fields
}
```
CookieVerifier verifies JWTs carried in a named cookie as specified by a
JWTCookieValidatorConfig.

### Methods

```go
func (cv *CookieVerifier) ClearCookie(rw http.ResponseWriter)
```
ClearCookie requests the removal of the cookie by the client.


```go
func (cv *CookieVerifier) Name() string
```
Name returns the name of the cookie that tokens are read from.


```go
func (cv *CookieVerifier) Parse(_ context.Context, token []byte) (jwt.Token, error)
```
Parse verifies the signature of token and returns it without validating any
of its claims, which is left to Validate so that the options implied by the
configuration, including any allowance for clock skew, are applied.


```go
func (cv *CookieVerifier) ParseAndValidate(ctx context.Context, token []byte, validators ...jwt.ValidateOption) (jwt.Token, error)
```
ParseAndValidate parses and validates token as per Parse and Validate.


```go
func (cv *CookieVerifier) Validate(_ context.Context, token jwt.Token, validators ...jwt.ValidateOption) error
```
Validate validates token using the configured issuer, audience and clock
skew followed by any additional validators supplied.


```go
func (cv *CookieVerifier) ValidateRequest(ctx context.Context, r *http.Request, validators ...jwt.ValidateOption) (jwt.Token, error)
```
ValidateRequest reads the configured cookie from r and parses and validates
the token that it contains. ErrNoCookie is returned if the request does not
carry the cookie.




### Type ED25519
```go
type ED25519 struct{}
```
ED25519 is the JWKKey implementation for keys created by NewED25519KeyInfo,
registered under the jwa.EdDSAEd25519 algorithm name (see KeyExtra). It
signs and verifies using the classic, widely supported "EdDSA" JWS algorithm
rather than the JWA name it is registered under, since the two name the same
Ed25519 signature scheme and "EdDSA" remains the more interoperable choice
on the wire.

### Methods

```go
func (e ED25519) PublicKey(info keys.Info) (jwk.Key, error)
```
PublicKey implements JWKKey by importing the ed25519 public key stored in
info's extra information, which must be base64, standard encoding, of the 32
byte public key.


```go
func (e ED25519) Signer(info keys.Info) (Signer, error)
```
Signer implements JWKKey by importing the ed25519 private key stored as
info's token, which must be base64, standard encoding, of the 64 byte
private key.




### Type JWKKey
```go
type JWKKey interface {
	Signer(keys.Info) (Signer, error)
	PublicKey(keys.Info) (jwk.Key, error)
}
```
JWKKey defines the interface that must be implemented by any algorithm
that can create signers and public keys from key material and associated
metadata, see KeyExtra. Implementations register themselves under an
algorithm name using algoRegistry, see NewED25519KeyInfo/ED25519 for the
pattern to follow when adding another algorithm.


### Type JWTCookieConfig
```go
type JWTCookieConfig struct {
	Name                     string `yaml:"name" doc:"cookie-name,jwt,name of the authentication cookie to set"`
	cookies.ScopeAndDuration `yaml:",inline" doc:"cookie and token scope and duration"`
	Insecure                 bool `yaml:"insecure" doc:"insecure,false,whether to allow insecure (non-HTTPS) connections"`
}
```

### Methods

```go
func (c JWTCookieConfig) Validate() error
```




### Type JWTCookieSignerConfig
```go
type JWTCookieSignerConfig struct {
	JWTCookieConfig `yaml:"cookie" doc:"jwt cookie config"`
	JWTSignerConfig `yaml:",inline" doc:"jwt info"`
}
```
JWTCookieSignerConfig provides configuration for a cookie storing a JWT.

### Methods

```go
func (c JWTCookieSignerConfig) NewCookieSigner(ctx context.Context, spec keys.KeySpec) (*CookieSigner, error)
```
NewCookieSigner returns a CookieSigner that signs with the key identified by
spec, obtained as per SignerForKey.


```go
func (c JWTCookieSignerConfig) Validate() error
```


```go
func (c JWTCookieSignerConfig) VerifierConfig() JWTCookieValidatorConfig
```
VerifierConfig returns the cookie validator configuration implied
by the cookie signer configuration, ie. the same cookie name, scope,
duration, insecure setting, issuer, audience, subject and claims.
Its ValidationTimeSkew is left at zero: a signer validating tokens that it
issued itself has no need to allow for clock drift between machines. It is
intended for use by a service that both issues and verifies its own cookies;
the verification key(s) must still be supplied separately when constructing
the CookieVerifier, since neither config carries key material.




### Type JWTCookieValidatorConfig
```go
type JWTCookieValidatorConfig struct {
	JWTCookieConfig    `yaml:"cookie" doc:"jwt cookie config"`
	ValidationTimeSkew time.Duration `yaml:"validation_time_skew" doc:"allowed time skew for cookie and token validation"`
	JWTValidatorConfig `yaml:",inline" doc:"jwt info"`
}
```
JWTCookieValidatorConfig provides configuration for verifying a JWT stored
in a cookie.

### Methods

```go
func (c JWTCookieValidatorConfig) NewCookieVerifier(ctx context.Context, verificationKeys ...keys.Info) (*CookieVerifier, error)
```
NewCookieVerifier returns a CookieVerifier that verifies tokens against
verificationKeys, obtained as per KeySetForKeys.


```go
func (c JWTCookieValidatorConfig) Validate() error
```




### Type JWTIssuerOption
```go
type JWTIssuerOption func(*jwtIssuerOptions)
```
JWTIssuerOption configures a JWTIssuer handler.

### Functions

```go
func WithAllowedRedirects(allowed ...string) JWTIssuerOption
```
WithAllowedRedirects configures an allowlist of permitted redirect
destinations (URLs or origins) for the redirect query parameter.


```go
func WithAudience(audience ...string) JWTIssuerOption
```
WithAudience sets the "aud" claim of issued tokens.


```go
func WithClaims(claims map[string]any) JWTIssuerOption
```
WithClaims adds or replaces multiple custom claims in issued tokens.
If any key is a reserved standard JWT claim (iss, sub, aud, exp, nbf, iat,
jti), NewJWTIssuer returns ErrReservedClaim.


```go
func WithDirect(enable bool) JWTIssuerOption
```
WithDirect explicitly enables or disables writing the token in the HTTP
response body. If no cookie is configured, direct issuance defaults to true.


```go
func WithExpiration(d time.Duration) JWTIssuerOption
```
WithExpiration sets the token validity duration relative to its issuance
time. Defaults to 1 hour.


```go
func WithExpiresIn(d time.Duration) JWTIssuerOption
```
WithExpiresIn is an alias for WithExpiration.


```go
func WithInsecureCookie(name string, scope cookies.ScopeAndDuration) JWTIssuerOption
```
WithInsecureCookie configures the handler to set the token in a plain HTTP
cookie (see cookies.T) named name, scoped and expiring as specified by
scope, without the Secure, HttpOnly or SameSiteStrictMode attributes that
WithSecureCookie applies. If scope.Duration is zero, the cookie expires
along with the token itself (see WithExpiration). Only one cookie option may
be specified.


```go
func WithIssuer(issuer string) JWTIssuerOption
```
WithIssuer sets the "iss" claim of issued tokens.


```go
func WithJSON(enable bool) JWTIssuerOption
```
WithJSON configures direct token issuance to output JSON format ({"token":
"..."}).


```go
func WithLogger(logger *slog.Logger) JWTIssuerOption
```
WithLogger sets the structured logger for issuance events and errors.


```go
func WithNotBefore(offset time.Duration) JWTIssuerOption
```
WithNotBefore sets the "nbf" claim offset relative to token issuance time.


```go
func WithRedirect(url string) JWTIssuerOption
```
WithRedirect configures an HTTP redirect destination after cookie issuance.


```go
func WithRedirectAllowlist(allowed ...string) JWTIssuerOption
```
WithRedirectAllowlist is an alias for WithAllowedRedirects.


```go
func WithRedirectQueryParam(paramName string) JWTIssuerOption
```
WithRedirectQueryParam configures the name of a query parameter (e.g.
"redirect") that specifies the redirect URL after cookie issuance. The
destination is restricted to same-origin relative paths (e.g. "/dashboard")
unless explicitly permitted by WithAllowedRedirects. If the parameter
contains an untrusted or invalid redirect destination, it is ignored and the
handler falls back to WithRedirect (if configured).


```go
func WithSecureCookie(name string, scope cookies.ScopeAndDuration) JWTIssuerOption
```
WithSecureCookie configures the handler to set the token in a secure HTTP
cookie (see cookies.Secure) named name, scoped and expiring as specified by
scope. If scope.Duration is zero, the cookie expires along with the token
itself (see WithExpiration). Only one cookie option may be specified.


```go
func WithSubject(subject string) JWTIssuerOption
```
WithSubject sets the "sub" claim of issued tokens.




### Type JWTSignerConfig
```go
type JWTSignerConfig struct {
	Issuer   string            `yaml:"jwt_issuer" doc:"jwt issuer"`
	Audience []string          `yaml:"jwt_audience" doc:"jwt audience"`
	Duration time.Duration     `yaml:"jwt_duration" doc:"duration,24h,validity duration of the issued JWT"`
	Subject  string            `yaml:"jwt_subject" doc:"jwt subject, always included as 'sub' claim if provided"`
	Claims   map[string]string `yaml:"jwt_claims" doc:"additional claims to include in issued JWTs"`
}
```
JWTSignerConfig provides configuration for signing JSON Web Tokens (JWTs).

### Methods

```go
func (c JWTSignerConfig) Builder(expiresIn time.Duration) *jwt.Builder
```
Builder returns a jwt.Builder with the issued at, issuer, audience, subject
and claims set from the configuration; subject and claims are only set if
configured, and either can still be overridden by the caller before Build,
since a later call to Subject or Claim on the same builder simply replaces
the earlier one. The expiration claim is set to expiresIn from now if it
is positive, or to c.Duration from now if expiresIn is not positive and
c.Duration is.


```go
func (c JWTSignerConfig) Validate() error
```




### Type JWTValidatorConfig
```go
type JWTValidatorConfig struct {
	Issuer   string            `yaml:"jwt_issuer" doc:"jwt issuer"`
	Audience []string          `yaml:"jwt_audience" doc:"jwt audience"`
	Subject  string            `yaml:"jwt_subject" doc:"jwt subject, always expected as 'sub' claim if provided"`
	Claims   map[string]string `yaml:"jwt_claims" doc:"additional claims to expect in the JWT"`
}
```
JWTValidatorConfig provides configuration for verifying JSON Web Tokens
(JWTs) for a given issuer and audience. Multiple verification keys can be
specified to allow for key rotation.

### Methods

```go
func (c JWTValidatorConfig) Validate() error
```


```go
func (c JWTValidatorConfig) ValidateOptions() []jwt.ValidateOption
```
ValidateOptions returns the validation options implied by the configuration,
namely that a token must have been issued by the configured issuer and must
be intended for at least one of the configured audiences. Claims entries
that shadow a reserved claim (see ErrReservedClaim) are skipped: Validate
already rejects a configuration containing one, but ValidateOptions may be
called independently of Validate, and standard claims like exp/nbf/iat are
not strings, so a jwt.WithClaimValue for one would never match and would
silently reject every otherwise-valid token.




### Type KeyExtra
```go
type KeyExtra struct {
	Algorithm string `json:"algorithm" yaml:"algorithm"`
	PublicKey string `json:"public_key" yaml:"public_key"`
}
```
KeyExtra describes the optional metadata that may be stored in the 'extra'
field of a keys.Info alongside the key material itself, ie.:

    key_id: jwt-signing-key
    token: <base64 encoded key material>
    extra:
      algorithm: Ed25519
      public_key: <base64 encoded public key>

All key material is base64 encoded using the standard encoding. Algorithm
selects the JWKKey implementation, registered under that name, used to turn
the key material into a Signer or public jwk.Key; see NewED25519KeyInfo for
the sole implementation currently provided by this package. PublicKey holds
the public half of the key, required by a verification key since it is not
derived from the token.


### Type Signer
```go
type Signer interface {
	Sign(context.Context, jwt.Token) ([]byte, error)
	PublicKey() (jwk.Key, error)
}
```
Signer is an interface for signing and verifying JWTs.

### Functions

```go
func NewSigner(jwkKey jwk.Key, id string, algo jwa.SignatureAlgorithm) (Signer, error)
```
NewSigner creates a new Signer instance with the given private key and key
ID.


```go
func NewSignerFromContext(ctx context.Context, user, id string) (Signer, error)
```
NewSignerFromContext returns a Signer for the key identified by user
and id, which is read from the keys.InMemoryKeyStore stored in ctx (see
keys.ContextWithKeyStore). ErrNoKeyStore or ErrKeyNotFound are returned if
the key is not available.


```go
func NewSignerFromKeyInfo(ctx context.Context, info keys.Info) (Signer, error)
```
NewSignerFromKeyInfo returns a Signer for the key material in info, using
the JWKKey implementation registered for the algorithm named in its extra
information.


```go
func SignerForKey(ctx context.Context, spec keys.KeySpec) (Signer, error)
```
SignerForKey returns a Signer for the key identified by spec, which is read
from the keys.InMemoryKeyStore stored in ctx (see keys.ContextWithKeyStore)
and interpreted as described by KeyExtra. ErrNoKeyStore or ErrKeyNotFound
are returned if the key is not available.




### Type Validator
```go
type Validator interface {
	Parse(ctx context.Context, token []byte) (jwt.Token, error)
	Validate(ctx context.Context, token jwt.Token, validators ...jwt.ValidateOption) error
	ParseAndValidate(ctx context.Context, token []byte, validators ...jwt.ValidateOption) (jwt.Token, error)
}
```
Validator is an interface for validating JWTs.

### Functions

```go
func NewValidator(set jwk.Set) Validator
```
NewValidator creates a new Validator instance with the given key set.


```go
func ValidatorForKeys(ctx context.Context, keys ...keys.Info) (Validator, error)
```
ValidatorForKeys returns a Validator that verifies the signature of any
token signed by one of the provided keys.






## Examples
### [ExampleJWTIssuer](https://pkg.go.dev/cloudeng.io/webapp/webauth/jwtutil?tab=doc#example-JWTIssuer)

### [ExampleJWTCookieSignerConfig](https://pkg.go.dev/cloudeng.io/webapp/webauth/jwtutil?tab=doc#example-JWTCookieSignerConfig)
ExampleJWTCookieSignerConfig illustrates issuing a JWT in a cookie and
validating it on a subsequent request.

### [ExampleJWTSignerConfig](https://pkg.go.dev/cloudeng.io/webapp/webauth/jwtutil?tab=doc#example-JWTSignerConfig)
ExampleJWTSignerConfig illustrates creating a signer, and the matching
validator, from a YAML configuration and a key store held in a context.

### [ExampleJWTValidatorConfig](https://pkg.go.dev/cloudeng.io/webapp/webauth/jwtutil?tab=doc#example-JWTValidatorConfig)
ExampleJWTValidatorConfig illustrates a service that verifies tokens issued
elsewhere and hence holds public keys only. Multiple verification keys can
be supplied to allow for key rotation.




