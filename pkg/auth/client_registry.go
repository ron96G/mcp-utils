package auth

import (
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/ron96g/mcp-utils/pkg/log"
	"github.com/ron96g/mcp-utils/pkg/models"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

// ClientRegistry manages OAuth2 client registration and storage
type ClientRegistry interface {
	// Dynamic Client Registration (RFC 7591)
	RegisterClient(req *models.ClientRegistrationRequest) (*models.ClientRegistrationResponse, error)

	// Client Management
	GetClient(clientID string) (*models.DynamicClient, error)
	UpdateClient(clientID string, req *models.ClientRegistrationRequest) (*models.ClientRegistrationResponse, error)
	DeleteClient(clientID string) error
	ListClients(limit, offset int) ([]*models.DynamicClient, int, error)

	// Client Validation
	ValidateClient(clientID, clientSecret string) (*models.DynamicClient, error)
	IsClientActive(clientID string) bool

	// Cleanup
	CleanupExpiredClients() error
}

// ClientRegistryConfig holds configuration for the client registry
type ClientRegistryConfig struct {
	// Default values for client registration
	DefaultGrantTypes              []string `yaml:"default_grant_types"`
	DefaultResponseTypes           []string `yaml:"default_response_types"`
	DefaultTokenEndpointAuthMethod string   `yaml:"default_token_endpoint_auth_method"`
	DefaultScope                   string   `yaml:"default_scope"`

	// Registration policies
	RequireRedirectURI     bool `yaml:"require_redirect_uri"`
	RequireHTTPS           bool `yaml:"require_https"`
	AllowLocalhostRedirect bool `yaml:"allow_localhost_redirect"`
	MaxRedirectURIs        int  `yaml:"max_redirect_uris"`
	MaxClientNameLength    int  `yaml:"max_client_name_length"`

	// Client lifecycle
	ClientSecretExpirationTime    time.Duration `yaml:"client_secret_expiration_time"`
	InactiveClientCleanupInterval time.Duration `yaml:"inactive_client_cleanup_interval"`

	// Allowed patterns
	AllowedRedirectURIPatterns []string `yaml:"allowed_redirect_uri_patterns"`
	BlockedRedirectURIPatterns []string `yaml:"blocked_redirect_uri_patterns"`
}

// DefaultClientRegistryConfig returns sensible defaults
func DefaultClientRegistryConfig() *ClientRegistryConfig {
	return &ClientRegistryConfig{
		DefaultGrantTypes:              []string{models.GrantTypeAuthorizationCode, models.GrantTypeRefreshToken},
		DefaultResponseTypes:           []string{models.ResponseTypeCode},
		DefaultTokenEndpointAuthMethod: "none", // Public clients
		DefaultScope:                   models.ScopeMCP,
		RequireRedirectURI:             true,
		RequireHTTPS:                   false, // Allow HTTP for localhost
		AllowLocalhostRedirect:         true,
		MaxRedirectURIs:                10,
		MaxClientNameLength:            100,
		ClientSecretExpirationTime:     0, // No expiration for simplicity
		InactiveClientCleanupInterval:  24 * time.Hour,
		AllowedRedirectURIPatterns: []string{
			"^https://.*",                          // Any HTTPS
			"^http://localhost(:[0-9]+)?/.*",       // Localhost HTTP
			"^http://127\\.0\\.0\\.1(:[0-9]+)?/.*", // 127.0.0.1 HTTP
		},
		BlockedRedirectURIPatterns: []string{
			"^http://(?!localhost|127\\.0\\.0\\.1).*", // Block HTTP except localhost
		},
	}
}

// memoryClientRegistry implements ClientRegistry using in-memory storage
type memoryClientRegistry struct {
	config    *ClientRegistryConfig
	clients   map[string]*models.DynamicClient
	mu        sync.RWMutex
	validator *validator.Validate
	logger    *log.Logger
}

// NewMemoryClientRegistry creates a new in-memory client registry
func NewMemoryClientRegistry(config *ClientRegistryConfig) ClientRegistry {
	if config == nil {
		config = DefaultClientRegistryConfig()
	}

	registry := &memoryClientRegistry{
		config:    config,
		clients:   make(map[string]*models.DynamicClient),
		validator: validator.New(),
		logger:    log.WithComponent("client_registry"),
	}

	// Start cleanup goroutine
	go registry.cleanupWorker()

	return registry
}

// RegisterClient implements dynamic client registration (RFC 7591)
func (r *memoryClientRegistry) RegisterClient(req *models.ClientRegistrationRequest) (*models.ClientRegistrationResponse, error) {
	r.logger.Info().
		Str("client_name", req.ClientName).
		Int("redirect_uris_count", len(req.RedirectURIs)).
		Str("scope", req.Scope).
		Msg("Client registration request received")

	// Validate request
	if err := r.validateRegistrationRequest(req); err != nil {
		r.logger.Warn().Err(err).Msg("Client registration validation failed")
		return nil, fmt.Errorf("invalid client metadata: %w", err)
	}

	// Generate client credentials
	clientID := models.GenerateClientID()
	var clientSecret string
	var err error

	// Only generate client secret for confidential clients
	if req.TokenEndpointAuthMethod != "none" {
		clientSecret, err = models.GenerateClientSecret()
		if err != nil {
			r.logger.Error().Err(err).Msg("Failed to generate client secret")
			return nil, fmt.Errorf("failed to generate client secret: %w", err)
		}
	}

	// Set defaults
	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = r.config.DefaultGrantTypes
	}

	responseTypes := req.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = r.config.DefaultResponseTypes
	}

	tokenEndpointAuthMethod := req.TokenEndpointAuthMethod
	if tokenEndpointAuthMethod == "" {
		tokenEndpointAuthMethod = r.config.DefaultTokenEndpointAuthMethod
	}

	scope := req.Scope
	if scope == "" {
		scope = r.config.DefaultScope
	}

	// Create client
	now := time.Now()
	client := &models.DynamicClient{
		ID:                      uuid.New().String(),
		ClientID:                clientID,
		ClientName:              req.ClientName,
		ClientURI:               req.ClientURI,
		LogoURI:                 req.LogoURI,
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		Scope:                   scope,
		TokenEndpointAuthMethod: tokenEndpointAuthMethod,
		Contacts:                req.Contacts,
		TOSUri:                  req.TOSUri,
		PolicyURI:               req.PolicyURI,
		JWKSUri:                 req.JWKSUri,
		SoftwareID:              req.SoftwareID,
		SoftwareVersion:         req.SoftwareVersion,
		CreatedAt:               now,
		UpdatedAt:               now,
		IsActive:                true,
	}

	// Hash and set the client secret if it exists
	if clientSecret != "" {
		if err := client.SetClientSecret(clientSecret); err != nil {
			r.logger.Error().Err(err).Msg("Failed to hash client secret")
			return nil, fmt.Errorf("failed to process client secret: %w", err)
		}
	}

	// Store client
	r.mu.Lock()
	r.clients[clientID] = client
	r.mu.Unlock()

	r.logger.Info().
		Str("client_id", clientID).
		Str("client_name", client.ClientName).
		Bool("is_public", client.IsPublicClient()).
		Msg("Client registered successfully")

	// Create response
	var clientSecretExpiresAt int64
	if r.config.ClientSecretExpirationTime > 0 {
		clientSecretExpiresAt = now.Add(r.config.ClientSecretExpirationTime).Unix()
	}

	response := &models.ClientRegistrationResponse{
		ClientID:                clientID,
		ClientSecret:            clientSecret, // Return the plain text secret, not the hash
		ClientIDIssuedAt:        now.Unix(),
		ClientSecretExpiresAt:   clientSecretExpiresAt,
		RedirectURIs:            client.RedirectURIs,
		TokenEndpointAuthMethod: client.TokenEndpointAuthMethod,
		GrantTypes:              client.GrantTypes,
		ResponseTypes:           client.ResponseTypes,
		ClientName:              client.ClientName,
		ClientURI:               client.ClientURI,
		LogoURI:                 client.LogoURI,
		Scope:                   client.Scope,
		Contacts:                client.Contacts,
		TOSUri:                  client.TOSUri,
		PolicyURI:               client.PolicyURI,
		JWKSUri:                 client.JWKSUri,
		SoftwareID:              client.SoftwareID,
		SoftwareVersion:         client.SoftwareVersion,
	}

	return response, nil
}

// GetClient retrieves a client by ID
func (r *memoryClientRegistry) GetClient(clientID string) (*models.DynamicClient, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	client, exists := r.clients[clientID]
	if !exists {
		return nil, fmt.Errorf("client not found")
	}

	if !client.IsActive {
		return nil, fmt.Errorf("client is inactive")
	}

	return client, nil
}

// UpdateClient updates an existing client
func (r *memoryClientRegistry) UpdateClient(clientID string, req *models.ClientRegistrationRequest) (*models.ClientRegistrationResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	client, exists := r.clients[clientID]
	if !exists {
		return nil, fmt.Errorf("client not found")
	}

	// Validate request
	if err := r.validateRegistrationRequest(req); err != nil {
		return nil, fmt.Errorf("invalid client metadata: %w", err)
	}

	// Update client fields
	client.ClientName = req.ClientName
	client.ClientURI = req.ClientURI
	client.LogoURI = req.LogoURI
	client.RedirectURIs = req.RedirectURIs
	client.Contacts = req.Contacts
	client.TOSUri = req.TOSUri
	client.PolicyURI = req.PolicyURI
	client.JWKSUri = req.JWKSUri
	client.SoftwareVersion = req.SoftwareVersion
	client.UpdatedAt = time.Now()

	if req.Scope != "" {
		client.Scope = req.Scope
	}

	r.logger.Info().
		Str("client_id", clientID).
		Str("client_name", client.ClientName).
		Msg("Client updated successfully")

	// Create response
	var clientSecretExpiresAt int64
	if r.config.ClientSecretExpirationTime > 0 {
		clientSecretExpiresAt = client.CreatedAt.Add(r.config.ClientSecretExpirationTime).Unix()
	}

	response := &models.ClientRegistrationResponse{
		ClientID:                client.ClientID,
		ClientSecret:            "", // Don't return the hashed secret for updates
		ClientIDIssuedAt:        client.CreatedAt.Unix(),
		ClientSecretExpiresAt:   clientSecretExpiresAt,
		RedirectURIs:            client.RedirectURIs,
		TokenEndpointAuthMethod: client.TokenEndpointAuthMethod,
		GrantTypes:              client.GrantTypes,
		ResponseTypes:           client.ResponseTypes,
		ClientName:              client.ClientName,
		ClientURI:               client.ClientURI,
		LogoURI:                 client.LogoURI,
		Scope:                   client.Scope,
		Contacts:                client.Contacts,
		TOSUri:                  client.TOSUri,
		PolicyURI:               client.PolicyURI,
		JWKSUri:                 client.JWKSUri,
		SoftwareID:              client.SoftwareID,
		SoftwareVersion:         client.SoftwareVersion,
	}

	return response, nil
}

// DeleteClient deletes a client
func (r *memoryClientRegistry) DeleteClient(clientID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.clients[clientID]; !exists {
		return fmt.Errorf("client not found")
	}

	delete(r.clients, clientID)

	r.logger.Info().
		Str("client_id", clientID).
		Msg("Client deleted successfully")

	return nil
}

// ListClients returns a paginated list of clients
func (r *memoryClientRegistry) ListClients(limit, offset int) ([]*models.DynamicClient, int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Convert map to slice
	allClients := make([]*models.DynamicClient, 0, len(r.clients))
	for _, client := range r.clients {
		if client.IsActive {
			allClients = append(allClients, client)
		}
	}

	total := len(allClients)

	// Apply pagination
	start := offset
	if start > total {
		start = total
	}

	end := start + limit
	if end > total {
		end = total
	}

	if start >= end {
		return []*models.DynamicClient{}, total, nil
	}

	return allClients[start:end], total, nil
}

// ValidateClient validates client credentials
func (r *memoryClientRegistry) ValidateClient(clientID, clientSecret string) (*models.DynamicClient, error) {
	client, err := r.GetClient(clientID)
	if err != nil {
		return nil, err
	}

	// For public clients, no secret validation needed
	if client.IsPublicClient() {
		return client, nil
	}

	// For confidential clients, validate secret using bcrypt
	if !client.VerifyClientSecret(clientSecret) {
		r.logger.LogSecurityEvent("invalid_client_secret", "", "", "medium", map[string]interface{}{
			"client_id": clientID,
		})
		return nil, fmt.Errorf("invalid client credentials")
	}

	return client, nil
}

// IsClientActive checks if a client is active
func (r *memoryClientRegistry) IsClientActive(clientID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	client, exists := r.clients[clientID]
	return exists && client.IsActive
}

// CleanupExpiredClients removes expired or inactive clients
func (r *memoryClientRegistry) CleanupExpiredClients() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	cleanupCount := 0

	for clientID, client := range r.clients {
		// Check if client secret has expired
		if r.config.ClientSecretExpirationTime > 0 {
			expiryTime := client.CreatedAt.Add(r.config.ClientSecretExpirationTime)
			if now.After(expiryTime) && !client.IsPublicClient() {
				delete(r.clients, clientID)
				cleanupCount++
				r.logger.Info().
					Str("client_id", clientID).
					Msg("Cleaned up expired client")
			}
		}
	}

	if cleanupCount > 0 {
		r.logger.Info().
			Int("cleaned_up_count", cleanupCount).
			Msg("Client cleanup completed")
	}

	return nil
}

// validateRegistrationRequest validates a client registration request
func (r *memoryClientRegistry) validateRegistrationRequest(req *models.ClientRegistrationRequest) error {
	// Basic struct validation
	if err := r.validator.Struct(req); err != nil {
		return err
	}

	// Validate redirect URIs
	if len(req.RedirectURIs) == 0 && r.config.RequireRedirectURI {
		return fmt.Errorf("at least one redirect URI is required")
	}

	if len(req.RedirectURIs) > r.config.MaxRedirectURIs {
		return fmt.Errorf("too many redirect URIs (max: %d)", r.config.MaxRedirectURIs)
	}

	for _, uri := range req.RedirectURIs {
		if err := models.ValidateRedirectURI(uri); err != nil {
			return fmt.Errorf("invalid redirect URI %s: %w", uri, err)
		}

		if err := r.validateRedirectURIPolicy(uri); err != nil {
			return fmt.Errorf("redirect URI not allowed by policy %s: %w", uri, err)
		}
	}

	// Validate client name
	if err := models.ValidateClientName(req.ClientName); err != nil {
		return err
	}

	// Validate scope
	if err := models.ValidateScope(req.Scope); err != nil {
		return err
	}

	// Validate grant types
	for _, grantType := range req.GrantTypes {
		if !r.isGrantTypeAllowed(grantType) {
			return fmt.Errorf("grant type not allowed: %s", grantType)
		}
	}

	// Validate response types
	for _, responseType := range req.ResponseTypes {
		if !r.isResponseTypeAllowed(responseType) {
			return fmt.Errorf("response type not allowed: %s", responseType)
		}
	}

	return nil
}

// validateRedirectURIPolicy validates redirect URI against configured policies
func (r *memoryClientRegistry) validateRedirectURIPolicy(uri string) error {
	// Check blocked patterns first
	for _, pattern := range r.config.BlockedRedirectURIPatterns {
		if matched, _ := regexp.MatchString(pattern, uri); matched {
			return fmt.Errorf("redirect URI matches blocked pattern")
		}
	}

	// Check allowed patterns
	if len(r.config.AllowedRedirectURIPatterns) > 0 {
		allowed := false
		for _, pattern := range r.config.AllowedRedirectURIPatterns {
			if matched, _ := regexp.MatchString(pattern, uri); matched {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("redirect URI does not match any allowed pattern")
		}
	}

	return nil
}

// isGrantTypeAllowed checks if a grant type is allowed
func (r *memoryClientRegistry) isGrantTypeAllowed(grantType string) bool {
	allowedGrantTypes := []string{
		models.GrantTypeAuthorizationCode,
		models.GrantTypeRefreshToken,
		// Add more as needed
	}

	for _, allowed := range allowedGrantTypes {
		if grantType == allowed {
			return true
		}
	}

	return false
}

// isResponseTypeAllowed checks if a response type is allowed
func (r *memoryClientRegistry) isResponseTypeAllowed(responseType string) bool {
	allowedResponseTypes := []string{
		models.ResponseTypeCode,
		// Add more as needed
	}

	for _, allowed := range allowedResponseTypes {
		if responseType == allowed {
			return true
		}
	}

	return false
}

// cleanupWorker runs periodic cleanup
func (r *memoryClientRegistry) cleanupWorker() {
	ticker := time.NewTicker(r.config.InactiveClientCleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		if err := r.CleanupExpiredClients(); err != nil {
			r.logger.Error().Err(err).Msg("Failed to cleanup expired clients")
		}
	}
}
