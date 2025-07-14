package models

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

// Token Generation Utilities

// GenerateSecureToken generates a cryptographically secure random token
func GenerateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// GenerateAuthorizationCode generates a secure authorization code
func GenerateAuthorizationCode() (string, error) {
	return GenerateSecureToken(32) // 256 bits of entropy
}

// GenerateAccessTokenID generates a unique access token identifier
func GenerateAccessTokenID() string {
	return uuid.New().String()
}

// GenerateRefreshToken generates a secure refresh token
func GenerateRefreshToken() (string, error) {
	return GenerateSecureToken(32) // 256 bits of entropy
}

// GenerateClientID generates a unique client ID
func GenerateClientID() string {
	return uuid.New().String()
}

// GenerateClientSecret generates a secure client secret
func GenerateClientSecret() (string, error) {
	return GenerateSecureToken(48) // 384 bits of entropy
}

// GenerateState generates a secure state parameter
func GenerateState() (string, error) {
	return GenerateSecureToken(24) // 192 bits of entropy
}

// PKCE Utilities

// GeneratePKCEChallenge generates a PKCE code verifier and challenge
func GeneratePKCEChallenge() (verifier, challenge string, err error) {
	// Generate code verifier (43-128 characters, RFC 7636)
	verifierBytes := make([]byte, 32) // 256 bits
	if _, err := rand.Read(verifierBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate PKCE verifier: %w", err)
	}

	verifier = base64.RawURLEncoding.EncodeToString(verifierBytes)

	// Generate S256 challenge
	hash := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(hash[:])

	return verifier, challenge, nil
}

// VerifyPKCEChallenge verifies a PKCE code verifier against a challenge
func VerifyPKCEChallenge(verifier, challenge, method string) bool {
	switch method {
	case CodeChallengeMethodPlain:
		return verifier == challenge
	case CodeChallengeMethodS256:
		hash := sha256.Sum256([]byte(verifier))
		expectedChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
		return expectedChallenge == challenge
	default:
		return false
	}
}

// Validation Utilities

// ValidateRedirectURI validates a redirect URI according to OAuth 2.0 specifications
func ValidateRedirectURI(redirectURI string) error {
	if redirectURI == "" {
		return fmt.Errorf("redirect URI cannot be empty")
	}

	u, err := url.Parse(redirectURI)
	if err != nil {
		return fmt.Errorf("invalid redirect URI format: %w", err)
	}

	// Must be absolute URI
	if !u.IsAbs() {
		return fmt.Errorf("redirect URI must be absolute")
	}

	// Fragment must not be present
	if u.Fragment != "" {
		return fmt.Errorf("redirect URI must not contain fragment")
	}

	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)

	// For public clients (like CLI), allow localhost with any port
	if scheme == "http" && (host == "localhost" || host == "127.0.0.1" || strings.HasPrefix(host, "localhost:") || strings.HasPrefix(host, "127.0.0.1:")) {
		return nil
	}

	// For production clients, require HTTPS
	if scheme != "https" {
		return fmt.Errorf("redirect URI must use HTTPS (except for localhost)")
	}

	return nil
}

// ValidateScope validates OAuth 2.0 scopes
func ValidateScope(scope string) error {
	if scope == "" {
		return nil // Empty scope is allowed
	}

	// RFC 6749: scope values are case-sensitive and separated by spaces
	scopes := strings.Fields(scope)
	if len(scopes) == 0 {
		return nil
	}

	// Validate each scope
	scopeRegex := regexp.MustCompile(`^[a-zA-Z0-9\.\-_:]+$`)
	for _, s := range scopes {
		if !scopeRegex.MatchString(s) {
			return fmt.Errorf("invalid scope format: %s", s)
		}
	}

	return nil
}

// ValidateClientName validates client name for dynamic registration
func ValidateClientName(name string) error {
	if name == "" {
		return nil // Client name is optional
	}

	if len(name) > 100 {
		return fmt.Errorf("client name must be 100 characters or less")
	}

	// Basic validation - no control characters
	for _, r := range name {
		if r < 32 || r == 127 {
			return fmt.Errorf("client name contains invalid characters")
		}
	}

	return nil
}

// Scope Utilities

// ParseScopes parses a space-separated scope string into a slice
func ParseScopes(scope string) []string {
	if scope == "" {
		return nil
	}
	return strings.Fields(scope)
}

// JoinScopes joins a slice of scopes into a space-separated string
func JoinScopes(scopes []string) string {
	return strings.Join(scopes, " ")
}
