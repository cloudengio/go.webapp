package jwtutil

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

// CreateVerificationToken creates a compacted JWT containing the specified
// claim to be verified along with an expiration time, subject, issuer, and audience.
func CreateVerificationToken(ctx context.Context, s Signer, subject, claimKey string, claimValue any, expiresIn time.Duration, issuer, audience string) ([]byte, error) {
	now := time.Now()
	builder := jwt.NewBuilder().
		Subject(subject).
		IssuedAt(now).
		Expiration(now.Add(expiresIn)).
		Claim(claimKey, claimValue)

	if issuer != "" {
		builder.Issuer(issuer)
	}

	if audience != "" {
		builder.Audience([]string{audience})
	}

	tok, err := builder.Build()
	if err != nil {
		return nil, err
	}

	return s.Sign(ctx, tok)
}

// VerificationURL generates a verification URL by appending the signed
// verification token as a query parameter ("token") to the provided baseURL.
// The URL will encode any existing query parameters gracefully.
func VerificationURL(s Signer, baseURL string, tokenBytes []byte) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Set("token", string(tokenBytes))
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// ValidateVerificationToken parses the token via the provided Validator,
// performs standard JWT claim checks (Issuer, Audience, Expiration), and
// extracts the specified claim from the validated JWT structure.
func ValidateVerificationToken(ctx context.Context, v Validator, tokenString string, expectedSubject, expectedIssuer, expectedAudience, claimKey string, claimValue any) error {
	validators := []jwt.ValidateOption{
		jwt.WithSubject(expectedSubject),
	}

	if expectedIssuer != "" {
		validators = append(validators, jwt.WithIssuer(expectedIssuer))
	}
	if expectedAudience != "" {
		validators = append(validators, jwt.WithAudience(expectedAudience))
	}

	tok, err := v.ParseAndValidate(ctx, []byte(tokenString), validators...)
	if err != nil {
		return err
	}

	if err := tok.Get(claimKey, claimValue); err != nil {
		return fmt.Errorf("invalid or missing %q claim: %w", claimKey, err)
	}
	return nil
}
