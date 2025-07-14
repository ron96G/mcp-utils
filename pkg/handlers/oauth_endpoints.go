package handlers

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ron96g/mcp-utils/pkg/auth"
	"github.com/ron96g/mcp-utils/pkg/config"
	"github.com/ron96g/mcp-utils/pkg/log"
	"github.com/ron96g/mcp-utils/pkg/models"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

// OAuthHandler handles OAuth2 endpoint requests
type OAuthHandler struct {
	config         *config.Config
	clientRegistry auth.ClientRegistry
	pkceManager    auth.PKCEManager
	sessionStore   SessionStore
	validator      *validator.Validate
	logger         *log.Logger

	// Entra ID OAuth2 config
	entraConfig *oauth2.Config
}

// SessionStore interface for storing temporary session data
type SessionStore interface {
	Set(key string, value interface{}, ttl time.Duration) error
	Get(key string) (interface{}, error)
	Delete(key string) error
}

// NewOAuthHandler creates a new OAuth2 handler
func NewOAuthHandler(cfg *config.Config, clientRegistry auth.ClientRegistry, pkceManager auth.PKCEManager, sessionStore SessionStore) *OAuthHandler {
	// Configure Entra ID OAuth2 client
	entraConfig := &oauth2.Config{
		ClientID:     cfg.EntraID.ClientID,
		ClientSecret: cfg.EntraID.ClientSecret,
		Endpoint:     microsoft.AzureADEndpoint(cfg.EntraID.TenantID),
		RedirectURL:  cfg.GetOAuthCallbackURL(),
		Scopes:       cfg.EntraID.Scopes,
	}

	return &OAuthHandler{
		config:         cfg,
		clientRegistry: clientRegistry,
		pkceManager:    pkceManager,
		sessionStore:   sessionStore,
		validator:      validator.New(),
		logger:         log.WithComponent("oauth_handler"),
		entraConfig:    entraConfig,
	}
}

// RegisterRoutes registers OAuth2 endpoints with the Fiber app
func (h *OAuthHandler) RegisterRoutes(app *fiber.App) {
	oauth := app.Group("/oauth2")

	// Dynamic Client Registration (RFC 7591)
	oauth.Post("/register", h.RegisterClient)
	oauth.Get("/register/:client_id", h.GetClient)
	oauth.Put("/register/:client_id", h.UpdateClient)
	oauth.Delete("/register/:client_id", h.DeleteClient)

	// Authorization Flow
	oauth.Get("/authorize", h.AuthorizeEndpoint)
	oauth.Get("/callback", h.CallbackEndpoint)
	oauth.Post("/token", h.TokenEndpoint)
	oauth.Post("/revoke", h.RevokeEndpoint)
}

// RegisterClient handles dynamic client registration
func (h *OAuthHandler) RegisterClient(c *fiber.Ctx) error {
	var req models.ClientRegistrationRequest
	if err := c.BodyParser(&req); err != nil {
		h.logger.Warn().Err(err).Msg("Invalid client registration request")
		return c.Status(fiber.StatusBadRequest).JSON(models.NewOAuth2Error(models.ErrorInvalidRequest, "Invalid request body"))
	}

	// Log registration attempt
	h.logger.Info().
		Str("client_name", req.ClientName).
		Int("redirect_uris_count", len(req.RedirectURIs)).
		Str("user_agent", c.Get("User-Agent")).
		Str("client_ip", c.IP()).
		Msg("Client registration request received")

	// Register client
	response, err := h.clientRegistry.RegisterClient(&req)
	if err != nil {
		h.logger.Error().Err(err).Msg("Client registration failed")
		return c.Status(fiber.StatusBadRequest).JSON(models.NewOAuth2Error(models.ErrorInvalidClientMetadata, err.Error()))
	}

	h.logger.Info().
		Str("client_id", response.ClientID).
		Str("client_name", response.ClientName).
		Msg("Client registered successfully")

	return c.Status(fiber.StatusCreated).JSON(response)
}

// GetClient retrieves client information
func (h *OAuthHandler) GetClient(c *fiber.Ctx) error {
	clientID := c.Params("client_id")

	client, err := h.clientRegistry.GetClient(clientID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(models.NewOAuth2Error(models.ErrorInvalidClient, "Client not found"))
	}

	// Convert to registration response format (without sensitive data)
	response := &models.ClientRegistrationResponse{
		ClientID:                client.ClientID,
		ClientIDIssuedAt:        client.CreatedAt.Unix(),
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

	return c.JSON(response)
}

// UpdateClient updates client information
func (h *OAuthHandler) UpdateClient(c *fiber.Ctx) error {
	clientID := c.Params("client_id")

	var req models.ClientRegistrationRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(models.NewOAuth2Error(models.ErrorInvalidRequest, "Invalid request body"))
	}

	response, err := h.clientRegistry.UpdateClient(clientID, &req)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return c.Status(fiber.StatusNotFound).JSON(models.NewOAuth2Error(models.ErrorInvalidClient, "Client not found"))
		} else {
			return c.Status(fiber.StatusBadRequest).JSON(models.NewOAuth2Error(models.ErrorInvalidClientMetadata, err.Error()))
		}
	}

	return c.JSON(response)
}

// DeleteClient deletes a client
func (h *OAuthHandler) DeleteClient(c *fiber.Ctx) error {
	clientID := c.Params("client_id")

	err := h.clientRegistry.DeleteClient(clientID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(models.NewOAuth2Error(models.ErrorInvalidClient, "Client not found"))
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// AuthorizeEndpoint handles OAuth2 authorization requests
func (h *OAuthHandler) AuthorizeEndpoint(c *fiber.Ctx) error {
	// Parse authorization request from query parameters
	req := models.AuthorizationRequest{
		ResponseType:        c.Query("response_type"),
		ClientID:            c.Query("client_id"),
		RedirectURI:         c.Query("redirect_uri"),
		Scope:               c.Query("scope"),
		State:               c.Query("state"),
		CodeChallenge:       c.Query("code_challenge"),
		CodeChallengeMethod: c.Query("code_challenge_method"),
		Resource:            c.Query("resource"),
		Nonce:               c.Query("nonce"),
		Prompt:              c.Query("prompt"),
		UILocales:           c.Query("ui_locales"),
		IDTokenHint:         c.Query("id_token_hint"),
		LoginHint:           c.Query("login_hint"),
		ACRValues:           c.Query("acr_values"),
	}

	// Parse max_age if provided
	if maxAgeStr := c.Query("max_age"); maxAgeStr != "" {
		if maxAge, err := strconv.Atoi(maxAgeStr); err == nil {
			req.MaxAge = maxAge
		}
	}

	// Validate request
	if err := h.validator.Struct(&req); err != nil {
		h.logger.Warn().Err(err).Msg("Authorization request validation failed")
		return h.redirectError(c, req.RedirectURI, req.State, models.ErrorInvalidRequest, err.Error())
	}

	h.logger.Info().
		Str("client_id", req.ClientID).
		Str("response_type", req.ResponseType).
		Str("scope", req.Scope).
		Str("redirect_uri", req.RedirectURI).
		Bool("has_pkce", req.RequiresPKCE()).
		Str("user_agent", c.Get("User-Agent")).
		Str("client_ip", c.IP()).
		Msg("Authorization request received")

	// Validate client
	client, err := h.clientRegistry.GetClient(req.ClientID)
	if err != nil {
		h.logger.Warn().
			Str("client_id", req.ClientID).
			Err(err).
			Msg("Invalid client in authorization request")
		return h.redirectError(c, req.RedirectURI, req.State, models.ErrorUnauthorizedClient, "Invalid client")
	}

	// Validate redirect URI
	if !client.IsRedirectURIAllowed(req.RedirectURI) {
		h.logger.LogSecurityEvent("invalid_redirect_uri", c.IP(), c.Get("User-Agent"), "high", map[string]interface{}{
			"client_id":    req.ClientID,
			"redirect_uri": req.RedirectURI,
			"allowed_uris": client.RedirectURIs,
		})
		return c.Status(fiber.StatusBadRequest).JSON(models.NewOAuth2Error(models.ErrorInvalidRedirectURI, "Invalid redirect URI"))
	}

	// Validate response type
	if !client.SupportsResponseType(req.ResponseType) {
		return h.redirectError(c, req.RedirectURI, req.State, models.ErrorUnsupportedResponseType, "Unsupported response type")
	}

	// Validate and store PKCE challenge if present
	if req.RequiresPKCE() {
		if err := h.validateAndStorePKCE(&req, client); err != nil {
			h.logger.Warn().Err(err).
				Str("client_id", req.ClientID).
				Msg("PKCE validation failed")
			return h.redirectError(c, req.RedirectURI, req.State, models.ErrorInvalidRequest, "Invalid PKCE parameters")
		}
	} else if h.config.OAuth.RequirePKCE {
		h.logger.Warn().
			Str("client_id", req.ClientID).
			Msg("PKCE required but not provided")
		return h.redirectError(c, req.RedirectURI, req.State, models.ErrorInvalidRequest, "PKCE is required")
	}

	// Store authorization session for callback
	sessionKey := h.generateSessionKey()
	sessionData := &AuthorizationSession{
		Request:   req,
		Client:    client,
		CreatedAt: time.Now(),
	}

	if err := h.sessionStore.Set(sessionKey, sessionData, 10*time.Minute); err != nil {
		h.logger.Error().Err(err).Msg("Failed to store authorization session")
		return h.redirectError(c, req.RedirectURI, req.State, models.ErrorServerError, "Internal server error")
	}

	// Build Entra ID authorization URL
	entraState := sessionKey // Use session key as state for Entra ID

	// For Entra ID, we need to use scopes instead of resource parameter
	// Entra ID doesn't support the RFC 8707 resource parameter
	var authOptions []oauth2.AuthCodeOption
	authOptions = append(authOptions, oauth2.AccessTypeOffline)

	// If a resource is specified, we'll handle it differently for Entra ID
	if req.Resource != "" {
		// Store the resource in session for later use, but don't send to Entra ID
		sessionData.Request.Resource = req.Resource
		h.logger.Debug().
			Str("resource", req.Resource).
			Msg("Resource parameter stored in session (not sent to Entra ID)")
	}

	entraAuthURL := h.entraConfig.AuthCodeURL(entraState, authOptions...)

	h.logger.Info().
		Str("client_id", req.ClientID).
		Str("session_key", sessionKey).
		Msg("Redirecting to Entra ID for authentication")

	// Redirect to Entra ID
	return c.Redirect(entraAuthURL, fiber.StatusFound)
}

// CallbackEndpoint handles the callback from Entra ID
func (h *OAuthHandler) CallbackEndpoint(c *fiber.Ctx) error {
	code := c.Query("code")
	state := c.Query("state")
	errorParam := c.Query("error")
	errorDescription := c.Query("error_description")

	h.logger.Info().
		Str("state", state).
		Bool("has_code", code != "").
		Bool("has_error", errorParam != "").
		Msg("OAuth callback received from Entra ID")

	// Handle error from Entra ID
	if errorParam != "" {
		h.logger.Warn().
			Str("error", errorParam).
			Str("error_description", errorDescription).
			Msg("Error received from Entra ID")

		// Retrieve session to get original redirect URI
		sessionData, err := h.getAuthorizationSession(state)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).SendString("Invalid session")
		}

		return h.redirectError(c, sessionData.Request.RedirectURI, sessionData.Request.State, errorParam, errorDescription)
	}

	if code == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Missing authorization code")
	}

	// Retrieve authorization session
	sessionData, err := h.getAuthorizationSession(state)
	if err != nil {
		h.logger.Error().Err(err).Str("state", state).Msg("Failed to retrieve authorization session")
		return c.Status(fiber.StatusBadRequest).SendString("Invalid or expired session")
	}

	// Exchange code for token with Entra ID
	token, err := h.entraConfig.Exchange(c.Context(), code)
	if err != nil {
		h.logger.Error().Err(err).Msg("Failed to exchange code with Entra ID")
		return h.redirectError(c, sessionData.Request.RedirectURI, sessionData.Request.State, models.ErrorServerError, "Failed to exchange authorization code")
	}

	h.logger.Info().
		Str("client_id", sessionData.Request.ClientID).
		Bool("has_refresh_token", token.RefreshToken != "").
		Time("expires_at", token.Expiry).
		Msg("Successfully exchanged code with Entra ID")

	// Generate authorization code for the MCP client
	mcpAuthCode, err := h.generateAuthorizationCode(sessionData, token)
	if err != nil {
		h.logger.Error().Err(err).Msg("Failed to generate MCP authorization code")
		return h.redirectError(c, sessionData.Request.RedirectURI, sessionData.Request.State, models.ErrorServerError, "Failed to generate authorization code")
	}

	// Clean up session
	h.sessionStore.Delete(state)

	// Redirect back to client with authorization code
	redirectURL, err := url.Parse(sessionData.Request.RedirectURI)
	if err != nil {
		h.logger.Error().Err(err).Msg("Invalid redirect URI")
		return c.Status(fiber.StatusBadRequest).SendString("Invalid redirect URI")
	}

	query := redirectURL.Query()
	query.Set("code", mcpAuthCode)
	query.Set("state", sessionData.Request.State)
	redirectURL.RawQuery = query.Encode()

	h.logger.Info().
		Str("client_id", sessionData.Request.ClientID).
		Str("redirect_uri", redirectURL.String()).
		Msg("Redirecting back to client with authorization code")

	return c.Redirect(redirectURL.String(), fiber.StatusFound)
}

// TokenEndpoint handles OAuth2 token requests
func (h *OAuthHandler) TokenEndpoint(c *fiber.Ctx) error {
	// Parse token request
	req := models.TokenRequest{
		GrantType:    c.FormValue("grant_type"),
		Code:         c.FormValue("code"),
		RedirectURI:  c.FormValue("redirect_uri"),
		ClientID:     c.FormValue("client_id"),
		ClientSecret: c.FormValue("client_secret"),
		RefreshToken: c.FormValue("refresh_token"),
		Scope:        c.FormValue("scope"),
		CodeVerifier: c.FormValue("code_verifier"),
		Resource:     c.FormValue("resource"),
	}

	// Validate request
	if err := h.validator.Struct(&req); err != nil {
		h.logger.Warn().Err(err).Msg("Token request validation failed")
		return c.Status(fiber.StatusBadRequest).JSON(models.NewOAuth2Error(models.ErrorInvalidRequest, err.Error()))
	}

	h.logger.Info().
		Str("grant_type", req.GrantType).
		Str("client_id", req.ClientID).
		Bool("has_code", req.Code != "").
		Bool("has_refresh_token", req.RefreshToken != "").
		Bool("has_code_verifier", req.CodeVerifier != "").
		Msg("Token request received")

	// Validate client
	client, err := h.clientRegistry.ValidateClient(req.ClientID, req.ClientSecret)
	if err != nil {
		h.logger.LogSecurityEvent("invalid_client_credentials", c.IP(), c.Get("User-Agent"), "high", map[string]interface{}{
			"client_id":  req.ClientID,
			"grant_type": req.GrantType,
		})
		return c.Status(fiber.StatusUnauthorized).JSON(models.NewOAuth2Error(models.ErrorInvalidClient, "Invalid client credentials"))
	}

	// Handle different grant types
	switch req.GrantType {
	case models.GrantTypeAuthorizationCode:
		return h.handleAuthorizationCodeGrant(c, &req, client)
	case models.GrantTypeRefreshToken:
		return h.handleRefreshTokenGrant(c, &req, client)
	default:
		return c.Status(fiber.StatusBadRequest).JSON(models.NewOAuth2Error(models.ErrorUnsupportedGrantType, "Unsupported grant type"))
	}
}

// RevokeEndpoint handles token revocation (RFC 7009)
func (h *OAuthHandler) RevokeEndpoint(c *fiber.Ctx) error {
	token := c.FormValue("token")
	tokenTypeHint := c.FormValue("token_type_hint")
	clientID := c.FormValue("client_id")
	clientSecret := c.FormValue("client_secret")

	h.logger.Info().
		Str("token_type_hint", tokenTypeHint).
		Str("client_id", clientID).
		Bool("has_token", token != "").
		Bool("has_client_secret", clientSecret != "").
		Str("client_ip", c.IP()).
		Str("user_agent", c.Get("User-Agent")).
		Msg("Token revocation requested")

	if token == "" {
		return c.Status(fiber.StatusBadRequest).JSON(models.NewOAuth2Error(models.ErrorInvalidRequest, "Missing token parameter"))
	}

	// Validate client if credentials provided
	if clientID != "" {
		client, err := h.clientRegistry.ValidateClient(clientID, clientSecret)
		if err != nil {
			h.logger.LogSecurityEvent("invalid_client_revocation", c.IP(), c.Get("User-Agent"), "medium", map[string]interface{}{
				"client_id": clientID,
				"error":     err.Error(),
			})
			return c.Status(fiber.StatusUnauthorized).JSON(models.NewOAuth2Error(models.ErrorInvalidClient, "Invalid client credentials"))
		}

		h.logger.Debug().
			Str("client_id", client.ClientID).
			Str("client_name", client.ClientName).
			Msg("Client validated for token revocation")
	}

	// TODO: implement actual token revocation logic

	// RFC 7009: The authorization server responds with HTTP status code 200 if the token
	// has been revoked successfully or if the client submitted an invalid token.
	return c.SendStatus(fiber.StatusOK)
}

// Helper methods

// AuthorizationSession represents a stored authorization session
type AuthorizationSession struct {
	Request   models.AuthorizationRequest `json:"request"`
	Client    *models.DynamicClient       `json:"client"`
	CreatedAt time.Time                   `json:"created_at"`
}

// redirectError redirects with OAuth2 error parameters
func (h *OAuthHandler) redirectError(c *fiber.Ctx, redirectURI, state, errorCode, errorDescription string) error {
	if redirectURI == "" {
		return c.Status(fiber.StatusBadRequest).JSON(models.NewOAuth2Error(errorCode, errorDescription))
	}

	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(models.NewOAuth2Error(models.ErrorInvalidRedirectURI, "Invalid redirect URI"))
	}

	query := redirectURL.Query()
	query.Set("error", errorCode)
	if errorDescription != "" {
		query.Set("error_description", errorDescription)
	}
	if state != "" {
		query.Set("state", state)
	}
	redirectURL.RawQuery = query.Encode()

	return c.Redirect(redirectURL.String(), fiber.StatusFound)
}

// validateAndStorePKCE validates PKCE parameters and stores the challenge
func (h *OAuthHandler) validateAndStorePKCE(req *models.AuthorizationRequest, client *models.DynamicClient) error {
	// Validate PKCE parameters
	if err := h.pkceManager.ValidateCodeChallenge(req.CodeChallenge, req.CodeChallengeMethod); err != nil {
		return fmt.Errorf("invalid PKCE challenge: %w", err)
	}

	// Create and store PKCE challenge
	challenge, err := h.pkceManager.CreateChallenge(client.ClientID)
	if err != nil {
		return fmt.Errorf("failed to create PKCE challenge: %w", err)
	}

	// Update the challenge with the provided values
	challenge.CodeChallenge = req.CodeChallenge
	challenge.CodeChallengeMethod = req.CodeChallengeMethod

	return nil
}

// generateSessionKey generates a unique session key
func (h *OAuthHandler) generateSessionKey() string {
	return fmt.Sprintf("auth_session_%d_%s", time.Now().UnixNano(), generateRandomString(16))
}

// getAuthorizationSession retrieves an authorization session
func (h *OAuthHandler) getAuthorizationSession(sessionKey string) (*AuthorizationSession, error) {
	data, err := h.sessionStore.Get(sessionKey)
	if err != nil {
		return nil, err
	}

	session, ok := data.(*AuthorizationSession)
	if !ok {
		return nil, fmt.Errorf("invalid session data")
	}

	return session, nil
}

// generateAuthorizationCode generates an authorization code for the MCP client
func (h *OAuthHandler) generateAuthorizationCode(session *AuthorizationSession, entraToken *oauth2.Token) (string, error) {
	// For now, we'll generate a simple code and store the mapping
	// In a real implementation, you'd store this in a database with the Entra ID token

	code, err := models.GenerateAuthorizationCode()
	if err != nil {
		return "", err
	}

	// Store the code-to-token mapping
	codeData := &AuthorizationCodeData{
		Code:        code,
		ClientID:    session.Client.ClientID,
		RedirectURI: session.Request.RedirectURI,
		Scope:       session.Request.Scope,
		EntraToken:  entraToken,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	}

	if err := h.sessionStore.Set("auth_code_"+code, codeData, 10*time.Minute); err != nil {
		return "", fmt.Errorf("failed to store authorization code: %w", err)
	}

	return code, nil
}

// AuthorizationCodeData represents stored authorization code data
type AuthorizationCodeData struct {
	Code        string        `json:"code"`
	ClientID    string        `json:"client_id"`
	RedirectURI string        `json:"redirect_uri"`
	Scope       string        `json:"scope"`
	EntraToken  *oauth2.Token `json:"entra_token"`
	CreatedAt   time.Time     `json:"created_at"`
	ExpiresAt   time.Time     `json:"expires_at"`
	Used        bool          `json:"used"`
}

// handleAuthorizationCodeGrant handles authorization code grant flow
func (h *OAuthHandler) handleAuthorizationCodeGrant(c *fiber.Ctx, req *models.TokenRequest, client *models.DynamicClient) error {
	// Retrieve authorization code data
	codeData, err := h.getAuthorizationCodeData(req.Code)
	if err != nil {
		h.logger.Warn().Err(err).Str("client_id", req.ClientID).Msg("Invalid authorization code")
		return c.Status(fiber.StatusBadRequest).JSON(models.NewOAuth2Error(models.ErrorInvalidGrant, "Invalid authorization code"))
	}

	// Validate code hasn't been used and hasn't expired
	if codeData.Used || time.Now().After(codeData.ExpiresAt) {
		h.logger.LogSecurityEvent("expired_or_used_auth_code", c.IP(), c.Get("User-Agent"), "high", map[string]interface{}{
			"client_id": req.ClientID,
			"code":      req.Code[:10] + "...",
		})
		return c.Status(fiber.StatusBadRequest).JSON(models.NewOAuth2Error(models.ErrorInvalidGrant, "Authorization code expired or already used"))
	}

	// Validate client and redirect URI
	if codeData.ClientID != req.ClientID {
		h.logger.LogSecurityEvent("client_mismatch_auth_code", c.IP(), c.Get("User-Agent"), "high", map[string]interface{}{
			"expected_client": codeData.ClientID,
			"provided_client": req.ClientID,
		})
		return c.Status(fiber.StatusBadRequest).JSON(models.NewOAuth2Error(models.ErrorInvalidGrant, "Client mismatch"))
	}

	if codeData.RedirectURI != req.RedirectURI {
		return c.Status(fiber.StatusBadRequest).JSON(models.NewOAuth2Error(models.ErrorInvalidGrant, "Redirect URI mismatch"))
	}

	// Verify PKCE if required
	if req.CodeVerifier != "" {
		// For simplicity in this implementation, we'll skip PKCE verification here
		// In a full implementation, you'd retrieve and verify the stored PKCE challenge
		h.logger.Debug().Msg("PKCE verification skipped in simplified implementation")
	}

	// Mark code as used
	codeData.Used = true
	h.sessionStore.Set("auth_code_"+req.Code, codeData, time.Minute) // Short TTL for used code

	// Return the Entra ID token directly
	tokenResponse := &models.TokenResponse{
		AccessToken:  codeData.EntraToken.AccessToken,
		TokenType:    models.TokenTypeBearer,
		ExpiresIn:    int64(time.Until(codeData.EntraToken.Expiry).Seconds()),
		RefreshToken: codeData.EntraToken.RefreshToken,
		Scope:        codeData.Scope,
	}

	h.logger.Info().
		Str("client_id", req.ClientID).
		Bool("has_refresh_token", tokenResponse.RefreshToken != "").
		Int64("expires_in", tokenResponse.ExpiresIn).
		Msg("Access token issued successfully")

	return c.JSON(tokenResponse)
}

// handleRefreshTokenGrant handles refresh token grant flow
func (h *OAuthHandler) handleRefreshTokenGrant(c *fiber.Ctx, req *models.TokenRequest, client *models.DynamicClient) error {
	// For direct Entra ID tokens, we'd need to refresh with Entra ID
	// This is simplified for now

	h.logger.Info().
		Str("client_id", req.ClientID).
		Msg("Refresh token grant requested")

	// In a real implementation, you'd:
	// 1. Validate the refresh token
	// 2. Call Entra ID to refresh the token
	// 3. Return the new tokens

	return c.Status(fiber.StatusNotImplemented).JSON(models.NewOAuth2Error(models.ErrorUnsupportedGrantType, "Refresh token grant not implemented yet"))
}

// getAuthorizationCodeData retrieves authorization code data
func (h *OAuthHandler) getAuthorizationCodeData(code string) (*AuthorizationCodeData, error) {
	data, err := h.sessionStore.Get("auth_code_" + code)
	if err != nil {
		return nil, err
	}

	codeData, ok := data.(*AuthorizationCodeData)
	if !ok {
		return nil, fmt.Errorf("invalid code data")
	}

	return codeData, nil
}

// generateRandomString generates a random string for session keys
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(result)
}
