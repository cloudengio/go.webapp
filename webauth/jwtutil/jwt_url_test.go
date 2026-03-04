package jwtutil_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/url"
	"testing"
	"time"

	"cloudeng.io/webapp/webauth/jwtutil"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func newEd25519SignerValidator(t *testing.T, keyID string) (jwtutil.Signer, jwtutil.Validator) {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key pair: %v", err)
	}

	signer, err := jwtutil.NewED25519Signer(priv, keyID)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	pk, err := signer.PublicKey()
	if err != nil {
		t.Fatalf("failed to get public key: %v", err)
	}

	set := jwk.NewSet()
	if err := set.AddKey(pk); err != nil {
		t.Fatalf("failed to add key to set: %v", err)
	}

	validator := jwtutil.NewValidator(set)
	return signer, validator
}

func TestEmailVerification(t *testing.T) {
	ctx := context.Background()
	signer, validator := newEd25519SignerValidator(t, "email-key-001")

	emailAddress := "user@example.com"
	baseURL := "https://example.com/verify?source=email"
	issuer := "test-issuer"
	audience := "test-audience"
	expiresIn := 1 * time.Hour

	tokenBytes, err := jwtutil.CreateVerificationToken(ctx, signer, "email-verification", "email", emailAddress, expiresIn, issuer, audience)
	if err != nil {
		t.Fatalf("CreateVerificationToken failed: %v", err)
	}

	// Test 1: Generate URL
	verifURL, err := jwtutil.VerificationURL(ctx, signer, baseURL, tokenBytes)
	if err != nil {
		t.Fatalf("VerificationURL failed: %v", err)
	}

	u, err := url.Parse(verifURL)
	if err != nil {
		t.Fatalf("failed to parse generated URL: %v", err)
	}

	// Verify the original query param remains
	if got, want := u.Query().Get("source"), "email"; got != want {
		t.Errorf("got %v, want %v", got, want)
	}

	// Extract the token parameter
	tokenStr := u.Query().Get("token")
	if tokenStr == "" {
		t.Fatal("missing token query parameter in generated URL")
	}

	// Test 2: Validation Success
	var extractedEmail string
	err = jwtutil.ValidateVerificationToken(ctx, validator, tokenStr, "email-verification", issuer, audience, "email", &extractedEmail)
	if err != nil {
		t.Fatalf("ValidateVerificationToken failed: %v", err)
	}

	if got, want := extractedEmail, emailAddress; got != want {
		t.Errorf("got %v, want %v", got, want)
	}

	// Test 3: Validation Failure - Wrong Audience
	var extractedEmail2 string
	err = jwtutil.ValidateVerificationToken(ctx, validator, tokenStr, "email-verification", issuer, "wrong-audience", "email", &extractedEmail2)
	if err == nil {
		t.Fatal("expected validation failure due to wrong audience")
	}

	// Test 4: Validation Failure - Wrong Issuer
	var extractedEmail3 string
	err = jwtutil.ValidateVerificationToken(ctx, validator, tokenStr, "email-verification", "wrong-issuer", audience, "email", &extractedEmail3)
	if err == nil {
		t.Fatal("expected validation failure due to wrong issuer")
	}
}

func TestEmailVerificationExpiration(t *testing.T) {
	ctx := context.Background()
	signer, validator := newEd25519SignerValidator(t, "email-key-002")

	emailAddress := "user@example.com"
	issuer := "test-issuer"
	audience := "test-audience"

	// Create a token that expires instantly
	tokenBytes, err := jwtutil.CreateVerificationToken(ctx, signer, "email-verification", "email", emailAddress, -1*time.Minute, issuer, audience)
	if err != nil {
		t.Fatalf("CreateVerificationToken failed: %v", err)
	}

	var expectedEmail string
	err = jwtutil.ValidateVerificationToken(ctx, validator, string(tokenBytes), "email-verification", issuer, audience, "email", &expectedEmail)
	if err == nil {
		t.Fatal("expected validation failure due to expired token")
	}
	t.Logf("expected validation error: %v", err)
}
