# Package [cloudeng.io/webapp/webauth/jwtutil](https://pkg.go.dev/cloudeng.io/webapp/webauth/jwtutil?tab=doc)

```go
import cloudeng.io/webapp/webauth/jwtutil
```

Package jwtutil provides support for creating and verifying JSON Web Tokens
(JWTs) managed by the github.com/lestrrat-go/jwx/v3/jwk package. This
package provides simplified wrappers around the JWT signing and verification
process to allow for more convenient usage in web applications.

## Types
### Type ED25519Signer
```go
type ED25519Signer struct {
	// contains filtered or unexported fields
}
```
ED25519Signer implements the Signer interface using an Ed25519 private key.

### Functions

```go
func NewED25519Signer(priv ed25519.PrivateKey, id string) (ED25519Signer, error)
```
NewED25519Signer creates a new ED25519Signer instance with the given private
key and key ID.



### Methods

```go
func (s ED25519Signer) ParseAndValidate(ctx context.Context, tokenBytes []byte, validators ...jwt.ValidateOption) (jwt.Token, error)
```
ParseAndValidate parses and validates a JWT using the signer's key set.


```go
func (s ED25519Signer) PublicKey() (jwk.Key, error)
```


```go
func (s ED25519Signer) Sign(_ context.Context, token jwt.Token) ([]byte, error)
```




### Type Signer
```go
type Signer interface {
	Sign(context.Context, jwt.Token) ([]byte, error)
	PublicKey() (jwk.Key, error)
	Validator
}
```
Signer is an interface for signing and verifying JWTs.


### Type Validator
```go
type Validator interface {
	ParseAndValidate(ctx context.Context, token []byte, validators ...jwt.ValidateOption) (jwt.Token, error)
}
```

### Functions

```go
func NewValidator(set jwk.Set) Validator
```







