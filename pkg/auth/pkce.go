package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/ron96g/mcp-utils/pkg/log"
	"github.com/ron96g/mcp-utils/pkg/models"

	"github.com/google/uuid"
)

// PKCEManager handles PKCE challenge generation, storage, and verification
type PKCEManager interface {
	// Challenge Management
	CreateChallenge(clientID string) (*models.PKCEChallenge, error)
	GetChallenge(clientID, codeChallenge string) (*models.PKCEChallenge, error)
	VerifyAndConsumeChallenge(clientID, codeVerifier, codeChallenge, method string) error

	// Utilities
	GenerateCodeVerifier() (string, error)
	GenerateCodeChallenge(verifier, method string) (string, error)
	ValidateCodeVerifier(verifier string) error
	ValidateCodeChallenge(challenge, method string) error

	// Cleanup
	CleanupExpiredChallenges() error
}

// PKCEConfig holds configuration for PKCE management
type PKCEConfig struct {
	// Challenge lifetime
	ChallengeLifetime time.Duration `yaml:"challenge_lifetime"`

	// Code verifier constraints (RFC 7636)
	MinVerifierLength int `yaml:"min_verifier_length"`
	MaxVerifierLength int `yaml:"max_verifier_length"`

	// Supported methods
	SupportedMethods []string `yaml:"supported_methods"`

	// Cleanup interval
	CleanupInterval time.Duration `yaml:"cleanup_interval"`

	// Security settings
	RequirePKCE            bool `yaml:"require_pkce"`
	AllowPlainMethod       bool `yaml:"allow_plain_method"`
	EnforceS256Method      bool `yaml:"enforce_s256_method"`
	MaxChallengesPerClient int  `yaml:"max_challenges_per_client"`
}

// DefaultPKCEConfig returns sensible defaults for PKCE configuration
func DefaultPKCEConfig() *PKCEConfig {
	return &PKCEConfig{
		ChallengeLifetime:      10 * time.Minute, // RFC 7636 recommends short-lived
		MinVerifierLength:      43,               // RFC 7636 minimum
		MaxVerifierLength:      128,              // RFC 7636 maximum
		SupportedMethods:       []string{models.CodeChallengeMethodS256},
		CleanupInterval:        5 * time.Minute,
		RequirePKCE:            true,
		AllowPlainMethod:       false, // S256 is more secure
		EnforceS256Method:      true,
		MaxChallengesPerClient: 10, // Prevent abuse
	}
}

// memoryPKCEManager implements PKCEManager using in-memory storage
type memoryPKCEManager struct {
	config           *PKCEConfig
	challenges       map[string]*models.PKCEChallenge // key: challenge ID
	clientChallenges map[string][]string              // key: clientID, value: challenge IDs
	mu               sync.RWMutex
	logger           *log.Logger
}

// NewMemoryPKCEManager creates a new in-memory PKCE manager
func NewMemoryPKCEManager(config *PKCEConfig) PKCEManager {
	if config == nil {
		config = DefaultPKCEConfig()
	}

	manager := &memoryPKCEManager{
		config:           config,
		challenges:       make(map[string]*models.PKCEChallenge),
		clientChallenges: make(map[string][]string),
		logger:           log.WithComponent("pkce_manager"),
	}

	// Start cleanup goroutine
	go manager.cleanupWorker()

	return manager
}

// CreateChallenge creates and stores a new PKCE challenge for a client
func (m *memoryPKCEManager) CreateChallenge(clientID string) (*models.PKCEChallenge, error) {
	if clientID == "" {
		return nil, fmt.Errorf("client ID is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if client has too many active challenges
	if clientChallenges, exists := m.clientChallenges[clientID]; exists {
		if len(clientChallenges) >= m.config.MaxChallengesPerClient {
			m.logger.Warn().
				Str("client_id", clientID).
				Int("challenge_count", len(clientChallenges)).
				Msg("Client has too many active PKCE challenges")
			return nil, fmt.Errorf("too many active challenges for client")
		}
	}

	// Generate code verifier and challenge
	verifier, err := m.GenerateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("failed to generate code verifier: %w", err)
	}

	challenge, err := m.GenerateCodeChallenge(verifier, models.CodeChallengeMethodS256)
	if err != nil {
		return nil, fmt.Errorf("failed to generate code challenge: %w", err)
	}

	// Create challenge record
	now := time.Now()
	pkceChallenge := &models.PKCEChallenge{
		ID:                  uuid.New().String(),
		ClientID:            clientID,
		CodeChallenge:       challenge,
		CodeChallengeMethod: models.CodeChallengeMethodS256,
		CreatedAt:           now,
		ExpiresAt:           now.Add(m.config.ChallengeLifetime),
		Used:                false,
	}

	// Store challenge
	m.challenges[pkceChallenge.ID] = pkceChallenge

	// Update client's challenge list
	if m.clientChallenges[clientID] == nil {
		m.clientChallenges[clientID] = make([]string, 0)
	}
	m.clientChallenges[clientID] = append(m.clientChallenges[clientID], pkceChallenge.ID)

	m.logger.Debug().
		Str("client_id", clientID).
		Str("challenge_id", pkceChallenge.ID).
		Str("method", pkceChallenge.CodeChallengeMethod).
		Time("expires_at", pkceChallenge.ExpiresAt).
		Msg("PKCE challenge created")

	return pkceChallenge, nil
}

// GetChallenge retrieves a PKCE challenge by client ID and code challenge
func (m *memoryPKCEManager) GetChallenge(clientID, codeChallenge string) (*models.PKCEChallenge, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Find challenge for this client
	clientChallenges, exists := m.clientChallenges[clientID]
	if !exists {
		return nil, fmt.Errorf("no challenges found for client")
	}

	for _, challengeID := range clientChallenges {
		challenge, exists := m.challenges[challengeID]
		if !exists {
			continue
		}

		// Check if this is the matching challenge
		if challenge.CodeChallenge == codeChallenge && !challenge.Used && !challenge.IsExpired() {
			return challenge, nil
		}
	}

	return nil, fmt.Errorf("PKCE challenge not found or expired")
}

// VerifyAndConsumeChallenge verifies a PKCE code verifier and marks the challenge as used
func (m *memoryPKCEManager) VerifyAndConsumeChallenge(clientID, codeVerifier, codeChallenge, method string) error {
	// Validate inputs
	if err := m.ValidateCodeVerifier(codeVerifier); err != nil {
		m.logger.LogSecurityEvent("invalid_pkce_verifier", "", "", "medium", map[string]interface{}{
			"client_id": clientID,
			"error":     err.Error(),
		})
		return fmt.Errorf("invalid code verifier: %w", err)
	}

	if err := m.ValidateCodeChallenge(codeChallenge, method); err != nil {
		m.logger.LogSecurityEvent("invalid_pkce_challenge", "", "", "medium", map[string]interface{}{
			"client_id": clientID,
			"method":    method,
			"error":     err.Error(),
		})
		return fmt.Errorf("invalid code challenge: %w", err)
	}

	// Get and verify challenge
	challenge, err := m.GetChallenge(clientID, codeChallenge)
	if err != nil {
		m.logger.LogSecurityEvent("pkce_challenge_not_found", "", "", "high", map[string]interface{}{
			"client_id":      clientID,
			"code_challenge": codeChallenge[:10] + "...", // Log partial for debugging
		})
		return fmt.Errorf("PKCE challenge verification failed: %w", err)
	}

	// Verify the code verifier against the stored challenge
	if !m.verifyCodeVerifier(codeVerifier, challenge.CodeChallenge, challenge.CodeChallengeMethod) {
		m.logger.LogSecurityEvent("pkce_verification_failed", "", "", "high", map[string]interface{}{
			"client_id":             clientID,
			"challenge_id":          challenge.ID,
			"code_challenge_method": challenge.CodeChallengeMethod,
		})
		return fmt.Errorf("PKCE verification failed")
	}

	// Mark challenge as used
	m.mu.Lock()
	challenge.Used = true
	m.mu.Unlock()

	m.logger.Info().
		Str("client_id", clientID).
		Str("challenge_id", challenge.ID).
		Str("method", challenge.CodeChallengeMethod).
		Msg("PKCE challenge verified and consumed")

	return nil
}

// GenerateCodeVerifier generates a cryptographically secure code verifier
func (m *memoryPKCEManager) GenerateCodeVerifier() (string, error) {
	// RFC 7636: code verifier should have at least 256 bits of entropy
	// We'll use 32 bytes (256 bits) of randomness
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Encode using base64url without padding (RFC 7636)
	verifier := base64.RawURLEncoding.EncodeToString(bytes)

	// Validate the generated verifier
	if err := m.ValidateCodeVerifier(verifier); err != nil {
		return "", fmt.Errorf("generated verifier is invalid: %w", err)
	}

	return verifier, nil
}

// GenerateCodeChallenge generates a code challenge from a verifier using the specified method
func (m *memoryPKCEManager) GenerateCodeChallenge(verifier, method string) (string, error) {
	if err := m.ValidateCodeVerifier(verifier); err != nil {
		return "", fmt.Errorf("invalid code verifier: %w", err)
	}

	switch method {
	case models.CodeChallengeMethodPlain:
		if !m.config.AllowPlainMethod {
			return "", fmt.Errorf("plain method not allowed")
		}
		return verifier, nil

	case models.CodeChallengeMethodS256:
		hash := sha256.Sum256([]byte(verifier))
		challenge := base64.RawURLEncoding.EncodeToString(hash[:])
		return challenge, nil

	default:
		return "", fmt.Errorf("unsupported code challenge method: %s", method)
	}
}

// ValidateCodeVerifier validates a PKCE code verifier according to RFC 7636
func (m *memoryPKCEManager) ValidateCodeVerifier(verifier string) error {
	if verifier == "" {
		return fmt.Errorf("code verifier cannot be empty")
	}

	// Check length constraints (RFC 7636)
	if len(verifier) < m.config.MinVerifierLength {
		return fmt.Errorf("code verifier too short (min: %d)", m.config.MinVerifierLength)
	}

	if len(verifier) > m.config.MaxVerifierLength {
		return fmt.Errorf("code verifier too long (max: %d)", m.config.MaxVerifierLength)
	}

	// Check character constraints (RFC 7636: unreserved characters)
	// [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
	validPattern := regexp.MustCompile(`^[A-Za-z0-9\-._~]+$`)
	if !validPattern.MatchString(verifier) {
		return fmt.Errorf("code verifier contains invalid characters")
	}

	return nil
}

// ValidateCodeChallenge validates a PKCE code challenge
func (m *memoryPKCEManager) ValidateCodeChallenge(challenge, method string) error {
	if challenge == "" {
		return fmt.Errorf("code challenge cannot be empty")
	}

	// Validate method
	if !m.isSupportedMethod(method) {
		return fmt.Errorf("unsupported code challenge method: %s", method)
	}

	if m.config.EnforceS256Method && method != models.CodeChallengeMethodS256 {
		return fmt.Errorf("only S256 method is allowed")
	}

	switch method {
	case models.CodeChallengeMethodPlain:
		return m.ValidateCodeVerifier(challenge)

	case models.CodeChallengeMethodS256:
		// For S256, challenge should be base64url encoded SHA256 hash (43 characters)
		if len(challenge) != 43 {
			return fmt.Errorf("S256 code challenge must be 43 characters long")
		}

		// Validate base64url encoding
		validPattern := regexp.MustCompile(`^[A-Za-z0-9\-_]+$`)
		if !validPattern.MatchString(challenge) {
			return fmt.Errorf("S256 code challenge contains invalid characters")
		}

		return nil

	default:
		return fmt.Errorf("unsupported code challenge method: %s", method)
	}
}

// CleanupExpiredChallenges removes expired PKCE challenges
func (m *memoryPKCEManager) CleanupExpiredChallenges() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	expiredCount := 0

	// Clean up expired challenges
	for challengeID, challenge := range m.challenges {
		if challenge.IsExpired() || challenge.Used {
			delete(m.challenges, challengeID)
			expiredCount++

			// Remove from client's challenge list
			if clientChallenges, exists := m.clientChallenges[challenge.ClientID]; exists {
				for i, id := range clientChallenges {
					if id == challengeID {
						// Remove from slice
						m.clientChallenges[challenge.ClientID] = append(clientChallenges[:i], clientChallenges[i+1:]...)
						break
					}
				}

				// Clean up empty client entries
				if len(m.clientChallenges[challenge.ClientID]) == 0 {
					delete(m.clientChallenges, challenge.ClientID)
				}
			}
		}
	}

	if expiredCount > 0 {
		m.logger.Debug().
			Int("expired_count", expiredCount).
			Int("remaining_count", len(m.challenges)).
			Msg("PKCE challenge cleanup completed")
	}

	return nil
}

// verifyCodeVerifier verifies a code verifier against a stored challenge
func (m *memoryPKCEManager) verifyCodeVerifier(verifier, storedChallenge, method string) bool {
	switch method {
	case models.CodeChallengeMethodPlain:
		// For plain method, verifier should equal challenge
		return subtle.ConstantTimeCompare([]byte(verifier), []byte(storedChallenge)) == 1

	case models.CodeChallengeMethodS256:
		// For S256, hash the verifier and compare with stored challenge
		hash := sha256.Sum256([]byte(verifier))
		computedChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
		return subtle.ConstantTimeCompare([]byte(computedChallenge), []byte(storedChallenge)) == 1

	default:
		m.logger.Error().
			Str("method", method).
			Msg("Unsupported code challenge method in verification")
		return false
	}
}

// isSupportedMethod checks if a code challenge method is supported
func (m *memoryPKCEManager) isSupportedMethod(method string) bool {
	for _, supported := range m.config.SupportedMethods {
		if method == supported {
			return true
		}
	}
	return false
}

// cleanupWorker runs periodic cleanup of expired challenges
func (m *memoryPKCEManager) cleanupWorker() {
	ticker := time.NewTicker(m.config.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		if err := m.CleanupExpiredChallenges(); err != nil {
			m.logger.Error().Err(err).Msg("Failed to cleanup expired PKCE challenges")
		}
	}
}

// GetStats returns statistics about the PKCE manager
func (m *memoryPKCEManager) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	activeChallenges := 0
	expiredChallenges := 0
	usedChallenges := 0

	for _, challenge := range m.challenges {
		if challenge.Used {
			usedChallenges++
		} else if challenge.IsExpired() {
			expiredChallenges++
		} else {
			activeChallenges++
		}
	}

	return map[string]interface{}{
		"total_challenges":        len(m.challenges),
		"active_challenges":       activeChallenges,
		"expired_challenges":      expiredChallenges,
		"used_challenges":         usedChallenges,
		"clients_with_challenges": len(m.clientChallenges),
		"config": map[string]interface{}{
			"challenge_lifetime":        m.config.ChallengeLifetime.String(),
			"supported_methods":         m.config.SupportedMethods,
			"require_pkce":              m.config.RequirePKCE,
			"enforce_s256_method":       m.config.EnforceS256Method,
			"max_challenges_per_client": m.config.MaxChallengesPerClient,
		},
	}
}
