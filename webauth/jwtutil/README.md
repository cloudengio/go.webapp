# Package [cloudeng.io/webapp/webauth/jwtutil](https://pkg.go.dev/cloudeng.io/webapp/webauth/jwtutil?tab=doc)

```go
import cloudeng.io/webapp/webauth/jwtutil
```

Package jwtutil provides support for creating and verifying JSON Web Tokens
(JWTs) managed by the github.com/lestrrat-go/jwx/v3/jwk package. This
package provides simplified wrappers around the JWT signing and verification
process to allow for more convenient usage in web applications.

## Functions
### Func CreateVerificationToken
```go
func CreateVerificationToken(ctx context.Context, s Signer, claimKey string, claimValue any, expiresIn time.Duration, issuer, audience string) ([]byte, error)
```
CreateVerificationToken creates a compacted JWT containing the specified
claim to be verified along with an expiration time, subject, issuer,
and audience.

### Func ValidateVerificationToken
```go
func ValidateVerificationToken(ctx context.Context, v Validator, tokenString string, expectedIssuer, expectedAudience, claimKey string, claimValue any) error
```
ValidateVerificationToken parses the token via the provided Validator,
performs standard JWT claim checks (Issuer, Audience, Expiration), and
extracts the specified claim from the validated JWT structure.

### Func VerificationURL
```go
func VerificationURL(ctx context.Context, s Signer, baseURL, claimKey string, claimValue any, expiresIn time.Duration, issuer, audience string) (string, error)
```
VerificationURL generates a verification URL by appending the signed
verification token as a query parameter ("token") to the provided baseURL.
The URL will encode any existing query parameters gracefully.



## Types
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
	ParseAndValidate(ctx context.Context, token []byte, validators ...jwt.ValidateOption) (jwt.Token, error)
}
```
Validator is an interface for validating JWTs.

### Functions

```go
func NewValidator(set jwk.Set) Validator
```
NewValidator creates a new Validator instance with the given key set.







