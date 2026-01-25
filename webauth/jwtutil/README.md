# Package [cloudeng.io/webapp/webauth/jwtutil](https://pkg.go.dev/cloudeng.io/webapp/webauth/jwtutil?tab=doc)

```go
import cloudeng.io/webapp/webauth/jwtutil
```

Package jwtutil provides support for creating and verifying JSON Web Tokens
(JWTs) managed by the github.com/lestrrat-go/jwx/v3/jwk package. This
package provides simplified wrappers around the JWT signing and verification
process to allow for more convenient usage in web applications.

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







