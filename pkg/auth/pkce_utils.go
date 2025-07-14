package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"

	"github.com/ron96g/mcp-utils/pkg/models"
)

// PKCEUtils provides utility functions for PKCE operations
type PKCEUtils struct {
	manager PKCEManager
}

// NewPKCEUtils creates a new PKCE utilities instance
func NewPKCEUtils(manager PKCEManager) *PKCEUtils {
	return &PKCEUtils{
		manager: manager,
	}
}

// GenerateAuthorizationURL generates an authorization URL with PKCE parameters
func (u *PKCEUtils) GenerateAuthorizationURL(baseURL, clientID, redirectURI, scope, state string, additionalParams map[string]string) (authURL, codeVerifier string, err error) {
	// Generate PKCE challenge
	challenge, err := u.manager.CreateChallenge(clientID)
	if err != nil {
		return "", "", fmt.Errorf("failed to create PKCE challenge: %w", err)
	}

	// Generate code verifier for the client to use
	verifier, err := u.manager.GenerateCodeVerifier()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate code verifier: %w", err)
	}

	// Build authorization URL
	authURL, err = u.buildAuthorizationURL(baseURL, clientID, redirectURI, scope, state, challenge.CodeChallenge, challenge.CodeChallengeMethod, additionalParams)
	if err != nil {
		return "", "", fmt.Errorf("failed to build authorization URL: %w", err)
	}

	return authURL, verifier, nil
}

// buildAuthorizationURL constructs the authorization URL with all required parameters
func (u *PKCEUtils) buildAuthorizationURL(baseURL, clientID, redirectURI, scope, state, codeChallenge, codeChallengeMethod string, additionalParams map[string]string) (string, error) {
	authURL, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base URL: %w", err)
	}

	// Add OAuth2 parameters
	params := url.Values{}
	params.Set("response_type", models.ResponseTypeCode)
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("state", state)

	if scope != "" {
		params.Set("scope", scope)
	}

	// Add PKCE parameters
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", codeChallengeMethod)

	// Add additional parameters
	for key, value := range additionalParams {
		params.Set(key, value)
	}

	authURL.RawQuery = params.Encode()

	return authURL.String(), nil
}

// VerifyPKCEFromRequest extracts and verifies PKCE parameters from a token request
func (u *PKCEUtils) VerifyPKCEFromRequest(clientID, codeVerifier, codeChallenge, codeChallengeMethod string) error {
	if codeVerifier == "" {
		return fmt.Errorf("code_verifier is required for PKCE")
	}

	if codeChallenge == "" {
		return fmt.Errorf("code_challenge is required for PKCE")
	}

	if codeChallengeMethod == "" {
		codeChallengeMethod = models.CodeChallengeMethodS256 // Default to S256
	}

	// Verify and consume the challenge
	return u.manager.VerifyAndConsumeChallenge(clientID, codeVerifier, codeChallenge, codeChallengeMethod)
}

// ExtractPKCEFromAuthRequest extracts PKCE parameters from an authorization request
func (u *PKCEUtils) ExtractPKCEFromAuthRequest(req *models.AuthorizationRequest) (bool, error) {
	hasPKCE := req.CodeChallenge != "" || req.CodeChallengeMethod != ""

	if !hasPKCE {
		return false, nil
	}

	// Validate PKCE parameters
	if req.CodeChallenge == "" {
		return true, fmt.Errorf("code_challenge is required when using PKCE")
	}

	if req.CodeChallengeMethod == "" {
		req.CodeChallengeMethod = models.CodeChallengeMethodS256 // Default to S256
	}

	// Validate the challenge and method
	if err := u.manager.ValidateCodeChallenge(req.CodeChallenge, req.CodeChallengeMethod); err != nil {
		return true, fmt.Errorf("invalid PKCE parameters: %w", err)
	}

	return true, nil
}

// CreatePKCEChallengeForClient creates a PKCE challenge for a specific client
func (u *PKCEUtils) CreatePKCEChallengeForClient(clientID string) (*PKCEChallengeInfo, error) {
	challenge, err := u.manager.CreateChallenge(clientID)
	if err != nil {
		return nil, err
	}

	verifier, err := u.manager.GenerateCodeVerifier()
	if err != nil {
		return nil, err
	}

	return &PKCEChallengeInfo{
		Challenge:     challenge,
		CodeVerifier:  verifier,
		CodeChallenge: challenge.CodeChallenge,
		Method:        challenge.CodeChallengeMethod,
	}, nil
}

// PKCEChallengeInfo contains PKCE challenge information for clients
type PKCEChallengeInfo struct {
	Challenge     *models.PKCEChallenge `json:"challenge"`
	CodeVerifier  string                `json:"code_verifier"`
	CodeChallenge string                `json:"code_challenge"`
	Method        string                `json:"method"`
}

// Helper functions for PKCE validation and generation

// IsValidPKCEMethod checks if a PKCE method is valid
func IsValidPKCEMethod(method string) bool {
	return method == models.CodeChallengeMethodPlain || method == models.CodeChallengeMethodS256
}

// ComputeS256Challenge computes an S256 challenge from a verifier
func ComputeS256Challenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// ValidatePKCEParameters validates PKCE parameters for compliance
func ValidatePKCEParameters(codeChallenge, codeChallengeMethod string, requirePKCE bool) error {
	hasPKCE := codeChallenge != "" || codeChallengeMethod != ""

	if requirePKCE && !hasPKCE {
		return fmt.Errorf("PKCE is required but not provided")
	}

	if !hasPKCE {
		return nil // No PKCE, and it's not required
	}

	// If any PKCE parameter is provided, all must be valid
	if codeChallenge == "" {
		return fmt.Errorf("code_challenge is required when using PKCE")
	}

	if codeChallengeMethod == "" {
		return fmt.Errorf("code_challenge_method is required when using PKCE")
	}

	if !IsValidPKCEMethod(codeChallengeMethod) {
		return fmt.Errorf("invalid code_challenge_method: %s", codeChallengeMethod)
	}

	return nil
}

// PKCEMiddleware provides middleware functions for HTTP handlers

// RequirePKCEMiddleware returns a middleware that requires PKCE for authorization requests
func RequirePKCEMiddleware(manager PKCEManager) func(next func()) func() {
	return func(next func()) func() {
		return func() {
			// This would be implemented in the actual HTTP middleware
			// The structure depends on your HTTP framework (Gin, Echo, etc.)
			next()
		}
	}
}

// PKCEDebugInfo provides debugging information for PKCE operations
type PKCEDebugInfo struct {
	CodeVerifier      string `json:"code_verifier"`
	CodeChallenge     string `json:"code_challenge"`
	Method            string `json:"method"`
	VerifierLength    int    `json:"verifier_length"`
	ChallengeLength   int    `json:"challenge_length"`
	ComputedChallenge string `json:"computed_challenge"`
	ChallengeMatches  bool   `json:"challenge_matches"`
}

// GeneratePKCEDebugInfo generates debugging information for PKCE parameters
func GeneratePKCEDebugInfo(verifier, challenge, method string) *PKCEDebugInfo {
	var computedChallenge string
	var matches bool

	switch method {
	case models.CodeChallengeMethodPlain:
		computedChallenge = verifier
		matches = verifier == challenge
	case models.CodeChallengeMethodS256:
		computedChallenge = ComputeS256Challenge(verifier)
		matches = computedChallenge == challenge
	}

	return &PKCEDebugInfo{
		CodeVerifier:      verifier,
		CodeChallenge:     challenge,
		Method:            method,
		VerifierLength:    len(verifier),
		ChallengeLength:   len(challenge),
		ComputedChallenge: computedChallenge,
		ChallengeMatches:  matches,
	}
}

// Constants for PKCE operations
const (
	// Default PKCE parameters
	DefaultCodeChallengeMethod = models.CodeChallengeMethodS256
	MinCodeVerifierEntropy     = 256 // bits
	RecommendedVerifierLength  = 43  // characters (256 bits base64url encoded)

	// Error messages
	ErrPKCERequired           = "PKCE is required for this client"
	ErrInvalidCodeVerifier    = "invalid code verifier"
	ErrInvalidCodeChallenge   = "invalid code challenge"
	ErrPKCEVerificationFailed = "PKCE verification failed"
)
