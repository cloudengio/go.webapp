# Package [cloudeng.io/webapp/webauth/jwtutil](https://pkg.go.dev/cloudeng.io/webapp/webauth/jwtutil?tab=doc)

```go
import cloudeng.io/webapp/webauth/jwtutil
```

Package jwtutil provides support for creating and verifying JSON Web Tokens
(JWTs) managed by the github.com/lestrrat-go/jwx/v3/jwk package. This
package provides simplified wrappers around the JWT signing and verification
process to allow for more convenient usage in web applications.

## Variables
### ErrNoKeyStore, ErrKeyNotFound
```go
// ErrNoKeyStore is returned when the context supplied to one of the
// configuration driven constructors does not contain a
// keys.InMemoryKeyStore.
ErrNoKeyStore = errors.New("no key store in context")
// ErrKeyNotFound is returned when a key named by a configuration is not
// present in the key store obtained from the context.
ErrKeyNotFound = errors.New("key not found")

```

### ErrNoCookie
```go
ErrNoCookie = errors.New("no such cookie")

```
ErrNoCookie is returned when a request does not carry the cookie named by a
JWTCookieVerifierConfig.



## Functions
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
CreateVerificationToken creates a compacted JWT containing the specified
claim to be verified along with an expiration time, subject, issuer,
and audience.

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

### Func NewJWTIssuer
```go
func NewJWTIssuer(signer Signer, opts ...JWTIssuerOption) (http.Handler, error)
```
NewJWTIssuer creates a new http.Handler that issues JWTs using signer
according to the configured options. It returns an error if signer is nil or
if more than one cookie option is specified.

### Func NewJWTIssuerMust
```go
func NewJWTIssuerMust(signer Signer, opts ...JWTIssuerOption) http.Handler
```
NewJWTIssuerMust creates a new http.Handler that issues JWTs using signer,
and panics if an error occurs.

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
The URL will encode any existing query parameters gracefully.



## Types
### Type CookieSigner
```go
type CookieSigner struct {
	Signer
	// contains filtered or unexported fields
}
```
CookieSigner issues JWTs carried in a named, secure, cookie as specified
by a JWTCookieSignerConfig. It is also a Validator for the tokens that it
issues, applying the same issuer, audience and clock skew checks as the
CookieVerifier created from VerifierConfig.

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
NewToken returns a token for subject with the issuer, audience and duration
specified by the configuration along with any additional claims supplied.


```go
func (cs *CookieSigner) Parse(ctx context.Context, token []byte) (jwt.Token, error)
```
Parse verifies the signature of token and returns it without validating any
of its claims, as per Verifier.Parse.


```go
func (cs *CookieSigner) ParseAndValidate(ctx context.Context, token []byte, validators ...jwt.ValidateOption) (jwt.Token, error)
```
ParseAndValidate parses and validates token as per Parse and Validate.


```go
func (cs *CookieSigner) SetCookie(ctx context.Context, rw http.ResponseWriter, token jwt.Token) error
```
SetCookie signs token and sets the resulting cookie on rw.


```go
func (cs *CookieSigner) Validate(ctx context.Context, token jwt.Token, validators ...jwt.ValidateOption) error
```
Validate validates token using the issuer, audience and clock skew specified
by the configuration followed by any additional validators supplied.




### Type CookieVerifier
```go
type CookieVerifier struct {
	*Verifier
	// contains filtered or unexported fields
}
```
CookieVerifier verifies JWTs carried in a named cookie as specified by a
JWTCookieVerifierConfig.

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
func (cv *CookieVerifier) ValidateRequest(ctx context.Context, r *http.Request, validators ...jwt.ValidateOption) (jwt.Token, error)
```
ValidateRequest reads the configured cookie from r and parses and validates
the token that it contains. ErrNoCookie is returned if the request does not
carry the cookie.




### Type JWTCookieSignerConfig
```go
type JWTCookieSignerConfig struct {
	Name                     string        `yaml:"name" doc:"cookie name"`
	ValidationTimeSkew       time.Duration `yaml:"validation_time_skew" doc:"allowed time skew for cookie and token validation"`
	cookies.ScopeAndDuration `yaml:",inline" doc:"cookie and token scope and duration"`
	JWTSignerConfig          `yaml:",inline" doc:"jwt info"`
}
```
JWTCookieSignerConfig provides configuration for a cookie storing a JWT.

### Methods

```go
func (c JWTCookieSignerConfig) NewCookieSigner(ctx context.Context) (*CookieSigner, error)
```
NewCookieSigner returns a CookieSigner for the signing key named by the
configuration. The key is obtained as per JWTSignerConfig.NewSigner.


```go
func (c JWTCookieSignerConfig) Validate() error
```


```go
func (c JWTCookieSignerConfig) VerifierConfig() JWTCookieVerifierConfig
```
VerifierConfig returns the cookie verifier configuration implied by the
cookie signer configuration, ie. the same cookie name, scope, duration, time
skew, issuer and audience with the signing key as the sole verification key.
It is intended for use by a service that both issues and verifies its own
cookies.




### Type JWTCookieVerifierConfig
```go
type JWTCookieVerifierConfig struct {
	Name                     string        `yaml:"name" doc:"cookie name"`
	ValidationTimeSkew       time.Duration `yaml:"validation_time_skew" doc:"allowed time skew for cookie and token validation"`
	cookies.ScopeAndDuration `yaml:",inline" doc:"cookie and token scope and duration"`
	JWTVerifierConfig        `yaml:",inline" doc:"jwt info"`
}
```
JWTCookieVerifierConfig provides configuration for verifying a JWT stored in
a cookie.

### Methods

```go
func (c JWTCookieVerifierConfig) NewCookieVerifier(ctx context.Context) (*CookieVerifier, error)
```
NewCookieVerifier returns a CookieVerifier for the verification
keys named by the configuration. The keys are obtained as per
JWTVerifierConfig.NewValidator.


```go
func (c JWTCookieVerifierConfig) Validate() error
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
func WithClaim(key string, value any) JWTIssuerOption
```
WithClaim adds or replaces a custom claim in issued tokens.


```go
func WithClaims(claims map[string]any) JWTIssuerOption
```
WithClaims adds or replaces multiple custom claims in issued tokens.


```go
func WithCookie(name string) JWTIssuerOption
```
WithCookie configures the handler to set the token in a secure HTTP cookie
with the given name (alias for WithSecureCookie).


```go
func WithCookieDomain(domain string) JWTIssuerOption
```
WithCookieDomain sets the Domain attribute for issued cookies.


```go
func WithCookiePath(path string) JWTIssuerOption
```
WithCookiePath sets the Path attribute for issued cookies. Defaults to "/".


```go
func WithCookieSameSite(sameSite http.SameSite) JWTIssuerOption
```
WithCookieSameSite sets the SameSite attribute for issued cookies.


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
func WithInsecureCookie(name string) JWTIssuerOption
```
WithInsecureCookie configures the handler to set the token in a plain
HTTP cookie without forcing Secure and SameSiteStrictMode attributes. A
subsequent WithCookieSameSite option can be used to set a specific SameSite
mode. Only one cookie option may be specified.


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
func WithSecureCookie(name string) JWTIssuerOption
```
WithSecureCookie configures the handler to set the token in a secure HTTP
cookie with the given name. Only one cookie option may be specified.


```go
func WithSubject(subject string) JWTIssuerOption
```
WithSubject sets the "sub" claim of issued tokens.




### Type JWTSignerConfig
```go
type JWTSignerConfig struct {
	Issuer     string       `yaml:"jwt_issuer" doc:"jwt issuer"`
	Audience   []string     `yaml:"jwt_audience" doc:"jwt audience"`
	SigningKey keys.KeySpec `yaml:"jwt_signing_key" doc:"jwt signing key spec"`
}
```
JWTSignerConfig provides configuration for signing JSON Web Tokens (JWTs).

### Methods

```go
func (c JWTSignerConfig) Builder(expiresIn time.Duration) *jwt.Builder
```
Builder returns a jwt.Builder with the issued at, issuer and audience claims
set from the configuration. The expiration claim is set to expiresIn from
now if it is positive.


```go
func (c JWTSignerConfig) NewSigner(ctx context.Context) (Signer, error)
```
NewSigner returns a Signer for the signing key named by the configuration.
The key is read from the keys.InMemoryKeyStore stored in ctx (see
keys.ContextWithKeyStore) and is interpreted as described by KeyExtra.
ErrNoKeyStore or ErrKeyNotFound are returned if the key is not available.


```go
func (c JWTSignerConfig) Validate() error
```


```go
func (c JWTSignerConfig) VerifierConfig() JWTVerifierConfig
```
VerifierConfig returns the verifier configuration implied by the signer
configuration, namely the same issuer and audience with the signing key as
the sole verification key. It is intended for use by a service that both
issues and verifies its own tokens.




### Type JWTVerifierConfig
```go
type JWTVerifierConfig struct {
	Issuer           string         `yaml:"jwt_issuer" doc:"jwt issuer"`
	Audience         []string       `yaml:"jwt_audience" doc:"jwt audience"`
	VerificationKeys []keys.KeySpec `yaml:"jwt_verification_keys" doc:"jwt verification key specs"`
}
```
JWTVerifierConfig provides configuration for verifying JSON Web Tokens
(JWTs) for a given issuer and audience. Multiple verification keys can be
specified to allow for key rotation.

### Methods

```go
func (c JWTVerifierConfig) NewValidator(ctx context.Context) (Validator, error)
```
NewValidator returns a Validator for the verification keys named by the
configuration. The keys are read from the keys.InMemoryKeyStore stored
in ctx (see keys.ContextWithKeyStore) and are interpreted as described
by KeyExtra. The returned Validator will verify the signature of any
token signed by one of those keys but, unlike the Verifier returned by
NewVerifier, it does not itself check the issuer or audience claims.


```go
func (c JWTVerifierConfig) NewVerifier(ctx context.Context) (*Verifier, error)
```
NewVerifier returns a Verifier for the keys, issuer and audience named by
the configuration. The keys are obtained as per NewValidator.


```go
func (c JWTVerifierConfig) Validate() error
```


```go
func (c JWTVerifierConfig) ValidateOptions() []jwt.ValidateOption
```
ValidateOptions returns the validation options implied by the configuration,
namely that a token must have been issued by the configured issuer and must
be intended for at least one of the configured audiences.




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
      algorithm: EdDSA
      public_key: <base64 encoded public key>

Both fields are optional. Algorithm names a JWS signature algorithm (EdDSA,
RS256, ES256 etc) and defaults to EdDSA, which is the only algorithm for
which raw (ie. non-JWK) key material is supported. PublicKey is used by
verification keys whose public key cannot be derived from the stored token.


### Type Signer
```go
type Signer interface {
	Sign(context.Context, jwt.Token) ([]byte, error)
	PublicKey() (jwk.Key, error)
	Validator
}
```
Signer is an interface for signing and verifying JWTs.

### Functions

```go
func NewED25519Signer(priv ed25519.PrivateKey, id string) (Signer, error)
```
NewED25519Signer creates a new ED25519Signer instance with the given private
key and key ID.


```go
func NewSigner(jwkKey jwk.Key, id string, algo jwa.SignatureAlgorithm) (Signer, error)
```
NewSigner creates a new Signer instance with the given private key and key
ID.




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




### Type Verifier
```go
type Verifier struct {
	Validator
	// contains filtered or unexported fields
}
```
Verifier is a Validator that applies the issuer and audience checks implied
by the configuration it was created from, as well as any allowance for clock
skew, in addition to verifying the signature of a token.

### Methods

```go
func (v *Verifier) Parse(_ context.Context, token []byte) (jwt.Token, error)
```
Parse verifies the signature of token and returns it without validating any
of its claims, which is left to Validate so that the options implied by the
configuration are applied.


```go
func (v *Verifier) ParseAndValidate(ctx context.Context, token []byte, validators ...jwt.ValidateOption) (jwt.Token, error)
```
ParseAndValidate parses and validates token as per Parse and Validate.


```go
func (v *Verifier) Validate(ctx context.Context, token jwt.Token, validators ...jwt.ValidateOption) error
```
Validate validates token using the configured issuer, audience and clock
skew followed by any additional validators supplied.






## Examples
### [ExampleJWTIssuer](https://pkg.go.dev/cloudeng.io/webapp/webauth/jwtutil?tab=doc#example-JWTIssuer)

### [ExampleJWTCookieSignerConfig](https://pkg.go.dev/cloudeng.io/webapp/webauth/jwtutil?tab=doc#example-JWTCookieSignerConfig)
ExampleJWTCookieSignerConfig illustrates issuing a JWT in a cookie and
validating it on a subsequent request.

### [ExampleJWTSignerConfig](https://pkg.go.dev/cloudeng.io/webapp/webauth/jwtutil?tab=doc#example-JWTSignerConfig)
ExampleJWTSignerConfig illustrates creating a signer, and the matching
verifier, from a YAML configuration and a key store held in a context.

### [ExampleJWTVerifierConfig](https://pkg.go.dev/cloudeng.io/webapp/webauth/jwtutil?tab=doc#example-JWTVerifierConfig)
ExampleJWTVerifierConfig illustrates a service that verifies tokens issued
elsewhere and hence holds public keys only. Multiple verification keys can
be configured to allow for key rotation.




