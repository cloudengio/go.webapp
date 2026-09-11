# Package [cloudeng.io/webapp/webauth/jwtutil](https://pkg.go.dev/cloudeng.io/webapp/webauth/jwtutil?tab=doc)

```go
import cloudeng.io/webapp/webauth/jwtutil
```

Package jwtutil provides support for creating and verifying JSON Web Tokens
(JWTs) managed by the github.com/lestrrat-go/jwx/v3/jwk package. This
package provides simplified wrappers around the JWT signing and verification
process to allow for more convenient usage in web applications.

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






## Examples
### [ExampleJWTIssuer](https://pkg.go.dev/cloudeng.io/webapp/webauth/jwtutil?tab=doc#example-JWTIssuer)




