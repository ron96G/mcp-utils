package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/pkg/errors"
	"github.com/ron96g/mcp-utils/pkg/auth"
	"github.com/ron96g/mcp-utils/pkg/config"
	"github.com/ron96g/mcp-utils/pkg/log"
	"github.com/ron96g/mcp-utils/pkg/models"

	"github.com/go-playground/validator/v10"
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
	CompareAndSet(key string, expected, new interface{}, ttl time.Duration) (bool, error)
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

// RegisterRoutes registers OAuth2 endpoints with the router
func (h *OAuthHandler) RegisterRoutes(router chi.Router) {
	router.Route("/oauth2", func(oauth chi.Router) {
		// Dynamic Client Registration (RFC 7591)
		oauth.Post("/register", h.RegisterClient)
		oauth.Get("/register/{client_id}", h.GetClient)
		oauth.Put("/register/{client_id}", h.UpdateClient)
		oauth.Delete("/register/{client_id}", h.DeleteClient)

		// Authorization Flow
		oauth.Get("/authorize", h.AuthorizeEndpoint)
		oauth.Get("/callback", h.CallbackEndpoint)
		oauth.Post("/token", h.TokenEndpoint)
		oauth.Post("/revoke", h.RevokeEndpoint)
	})

}

// RegisterClient handles dynamic client registration
func (h *OAuthHandler) RegisterClient(w http.ResponseWriter, r *http.Request) {
	var req models.ClientRegistrationRequest
	if err := parseJSONBody(r, &req); err != nil {
		h.logger.Warn().Err(err).Msg("Invalid client registration request")
		h.writeJSONError(w, http.StatusBadRequest, models.ErrorInvalidRequest, "Invalid request body")
		return
	}

	// Log registration attempt
	h.logger.Info().
		Str("client_name", req.ClientName).
		Int("redirect_uris_count", len(req.RedirectURIs)).
		Str("user_agent", getUserAgent(r)).
		Str("client_ip", getClientIP(r)).
		Msg("Client registration request received")

	// Register client
	response, err := h.clientRegistry.RegisterClient(&req)
	if err != nil {
		h.logger.Error().Err(err).Msg("Client registration failed")
		h.writeJSONError(w, http.StatusBadRequest, models.ErrorInvalidClientMetadata, err.Error())
		return
	}

	h.logger.Info().
		Str("client_id", response.ClientID).
		Str("client_name", response.ClientName).
		Msg("Client registered successfully")

	h.writeJSONResponse(w, http.StatusCreated, response)
}

// GetClient retrieves client information
func (h *OAuthHandler) GetClient(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "client_id")
	client, err := h.clientRegistry.GetClient(clientID)
	if err != nil {
		h.writeJSONError(w, http.StatusNotFound, models.ErrorInvalidClient, "Client not found")
		return
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

	h.writeJSONResponse(w, http.StatusOK, response)
}

// UpdateClient updates client information
func (h *OAuthHandler) UpdateClient(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "client_id")

	var req models.ClientRegistrationRequest
	if err := parseJSONBody(r, &req); err != nil {
		h.writeJSONError(w, http.StatusBadRequest, models.ErrorInvalidRequest, "Invalid request body")
		return
	}

	response, err := h.clientRegistry.UpdateClient(clientID, &req)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.writeJSONError(w, http.StatusNotFound, models.ErrorInvalidClient, "Client not found")
		} else {
			h.writeJSONError(w, http.StatusBadRequest, models.ErrorInvalidClientMetadata, err.Error())
		}
		return
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// DeleteClient deletes a client
func (h *OAuthHandler) DeleteClient(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "client_id")

	err := h.clientRegistry.DeleteClient(clientID)
	if err != nil {
		h.writeJSONError(w, http.StatusNotFound, models.ErrorInvalidClient, "Client not found")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// AuthorizeEndpoint handles OAuth2 authorization requests
func (h *OAuthHandler) AuthorizeEndpoint(w http.ResponseWriter, r *http.Request) {
	// Parse authorization request from query parameters
	query := r.URL.Query()
	req := models.AuthorizationRequest{
		ResponseType:        query.Get("response_type"),
		ClientID:            query.Get("client_id"),
		RedirectURI:         query.Get("redirect_uri"),
		Scope:               query.Get("scope"),
		State:               query.Get("state"),
		CodeChallenge:       query.Get("code_challenge"),
		CodeChallengeMethod: query.Get("code_challenge_method"),
		Resource:            query.Get("resource"),
		Nonce:               query.Get("nonce"),
		Prompt:              query.Get("prompt"),
		UILocales:           query.Get("ui_locales"),
		IDTokenHint:         query.Get("id_token_hint"),
		LoginHint:           query.Get("login_hint"),
		ACRValues:           query.Get("acr_values"),
	}

	// Parse max_age if provided
	if maxAgeStr := query.Get("max_age"); maxAgeStr != "" {
		if maxAge, err := strconv.Atoi(maxAgeStr); err == nil {
			req.MaxAge = maxAge
		}
	}

	// Validate request
	if err := h.validator.Struct(&req); err != nil {
		h.logger.Warn().Err(err).Msg("Authorization request validation failed")
		h.redirectError(w, r, req.RedirectURI, req.State, models.ErrorInvalidRequest, err.Error())
		return
	}

	h.logger.Info().
		Str("client_id", req.ClientID).
		Str("response_type", req.ResponseType).
		Str("scope", req.Scope).
		Str("redirect_uri", req.RedirectURI).
		Bool("has_pkce", req.RequiresPKCE()).
		Str("user_agent", getUserAgent(r)).
		Str("client_ip", getClientIP(r)).
		Msg("Authorization request received")

	// Validate client
	client, err := h.clientRegistry.GetClient(req.ClientID)
	if err != nil {
		h.logger.Warn().
			Str("client_id", req.ClientID).
			Err(err).
			Msg("Invalid client in authorization request")
		h.redirectError(w, r, req.RedirectURI, req.State, models.ErrorUnauthorizedClient, "Invalid client")
		return
	}

	// Validate redirect URI
	if !client.IsRedirectURIAllowed(req.RedirectURI) {
		h.logger.LogSecurityEvent("invalid_redirect_uri", getClientIP(r), getUserAgent(r), "high", map[string]interface{}{
			"client_id":    req.ClientID,
			"redirect_uri": req.RedirectURI,
			"allowed_uris": client.RedirectURIs,
		})
		h.writeJSONError(w, http.StatusBadRequest, models.ErrorInvalidRedirectURI, "Invalid redirect URI")
		return
	}

	// Validate response type
	if !client.SupportsResponseType(req.ResponseType) {
		h.redirectError(w, r, req.RedirectURI, req.State, models.ErrorUnsupportedResponseType, "Unsupported response type")
		return
	}

	// Validate and store PKCE challenge if present
	if req.RequiresPKCE() {
		if err := h.validateAndStorePKCE(&req, client); err != nil {
			h.logger.Warn().Err(err).
				Str("client_id", req.ClientID).
				Msg("PKCE validation failed")
			h.redirectError(w, r, req.RedirectURI, req.State, models.ErrorInvalidRequest, "Invalid PKCE parameters")
			return
		}
	} else if h.config.OAuth.RequirePKCE {
		h.logger.Warn().
			Str("client_id", req.ClientID).
			Msg("PKCE required but not provided")
		h.redirectError(w, r, req.RedirectURI, req.State, models.ErrorInvalidRequest, "PKCE is required")
		return
	}

	// Store authorization session for callback
	sessionKey, err := h.generateSessionKey()
	if err != nil {
		h.logger.Error().
			Str("client_id", req.ClientID).
			Err(err)
		h.redirectError(w, r, req.RedirectURI, req.State, models.ErrorInvalidRequest, "Failed to create session")
	}
	sessionData := &AuthorizationSession{
		Request:   req,
		Client:    client,
		CreatedAt: time.Now(),
	}

	if err := h.sessionStore.Set(sessionKey, sessionData, 10*time.Minute); err != nil {
		h.logger.Error().Err(err).Msg("Failed to store authorization session")
		h.redirectError(w, r, req.RedirectURI, req.State, models.ErrorServerError, "Internal server error")
		return
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
	http.Redirect(w, r, entraAuthURL, http.StatusFound)
}

// CallbackEndpoint handles the callback from Entra ID
func (h *OAuthHandler) CallbackEndpoint(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	code := query.Get("code")
	state := query.Get("state")
	errorParam := query.Get("error")
	errorDescription := query.Get("error_description")

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
			http.Error(w, "Invalid session", http.StatusBadRequest)
			return
		}

		h.redirectError(w, r, sessionData.Request.RedirectURI, sessionData.Request.State, errorParam, errorDescription)
		return
	}

	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	// Retrieve authorization session
	sessionData, err := h.getAuthorizationSession(state)
	if err != nil {
		h.logger.Error().Err(err).Str("state", state).Msg("Failed to retrieve authorization session")
		http.Error(w, "Invalid or expired session", http.StatusBadRequest)
		return
	}

	// Exchange code for token with Entra ID
	token, err := h.entraConfig.Exchange(context.Background(), code)
	if err != nil {
		h.logger.Error().Err(err).Msg("Failed to exchange code with Entra ID")
		h.redirectError(w, r, sessionData.Request.RedirectURI, sessionData.Request.State, models.ErrorServerError, "Failed to exchange authorization code")
		return
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
		h.redirectError(w, r, sessionData.Request.RedirectURI, sessionData.Request.State, models.ErrorServerError, "Failed to generate authorization code")
		return
	}

	// Clean up session
	h.sessionStore.Delete(state)

	// Redirect back to client with authorization code
	redirectURL, err := url.Parse(sessionData.Request.RedirectURI)
	if err != nil {
		h.logger.Error().Err(err).Msg("Invalid redirect URI")
		http.Error(w, "Invalid redirect URI", http.StatusBadRequest)
		return
	}

	queryParams := redirectURL.Query()
	queryParams.Set("code", mcpAuthCode)
	queryParams.Set("state", sessionData.Request.State)
	redirectURL.RawQuery = queryParams.Encode()

	h.logger.Info().
		Str("client_id", sessionData.Request.ClientID).
		Str("redirect_uri", redirectURL.String()).
		Msg("Redirecting back to client with authorization code")

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// TokenEndpoint handles OAuth2 token requests
func (h *OAuthHandler) TokenEndpoint(w http.ResponseWriter, r *http.Request) {
	// Parse form data
	if err := r.ParseForm(); err != nil {
		h.logger.Warn().Err(err).Msg("Failed to parse form data")
		h.writeJSONError(w, http.StatusBadRequest, models.ErrorInvalidRequest, "Invalid form data")
		return
	}

	// Parse token request
	req := models.TokenRequest{
		GrantType:    r.FormValue("grant_type"),
		Code:         r.FormValue("code"),
		RedirectURI:  r.FormValue("redirect_uri"),
		ClientID:     r.FormValue("client_id"),
		ClientSecret: r.FormValue("client_secret"),
		RefreshToken: r.FormValue("refresh_token"),
		Scope:        r.FormValue("scope"),
		CodeVerifier: r.FormValue("code_verifier"),
		Resource:     r.FormValue("resource"),
	}

	// Validate request
	if err := h.validator.Struct(&req); err != nil {
		h.logger.Warn().Err(err).Msg("Token request validation failed")
		h.writeJSONError(w, http.StatusBadRequest, models.ErrorInvalidRequest, err.Error())
		return
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
		h.logger.LogSecurityEvent("invalid_client_credentials", getClientIP(r), getUserAgent(r), "high", map[string]interface{}{
			"client_id":  req.ClientID,
			"grant_type": req.GrantType,
		})
		h.writeJSONError(w, http.StatusUnauthorized, models.ErrorInvalidClient, "Invalid client credentials")
		return
	}

	// Handle different grant types
	switch req.GrantType {
	case models.GrantTypeAuthorizationCode:
		h.handleAuthorizationCodeGrant(w, r, &req, client)
	case models.GrantTypeRefreshToken:
		h.handleRefreshTokenGrant(w, r, &req, client)
	default:
		h.writeJSONError(w, http.StatusBadRequest, models.ErrorUnsupportedGrantType, "Unsupported grant type")
	}
}

// RevokeEndpoint handles token revocation (RFC 7009)
func (h *OAuthHandler) RevokeEndpoint(w http.ResponseWriter, r *http.Request) {
	// Parse form data
	if err := r.ParseForm(); err != nil {
		h.logger.Warn().Err(err).Msg("Failed to parse form data")
		h.writeJSONError(w, http.StatusBadRequest, models.ErrorInvalidRequest, "Invalid form data")
		return
	}

	token := r.FormValue("token")
	tokenTypeHint := r.FormValue("token_type_hint")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	h.logger.Info().
		Str("token_type_hint", tokenTypeHint).
		Str("client_id", clientID).
		Bool("has_token", token != "").
		Bool("has_client_secret", clientSecret != "").
		Str("client_ip", getClientIP(r)).
		Str("user_agent", getUserAgent(r)).
		Msg("Token revocation requested")

	if token == "" {
		h.writeJSONError(w, http.StatusBadRequest, models.ErrorInvalidRequest, "Missing token parameter")
		return
	}

	// Validate client if credentials provided
	if clientID != "" {
		client, err := h.clientRegistry.ValidateClient(clientID, clientSecret)
		if err != nil {
			h.logger.LogSecurityEvent("invalid_client_revocation", getClientIP(r), getUserAgent(r), "medium", map[string]interface{}{
				"client_id": clientID,
				"error":     err.Error(),
			})
			h.writeJSONError(w, http.StatusUnauthorized, models.ErrorInvalidClient, "Invalid client credentials")
			return
		}

		h.logger.Debug().
			Str("client_id", client.ClientID).
			Str("client_name", client.ClientName).
			Msg("Client validated for token revocation")
	}

	// TODO: implement actual token revocation logic

	// RFC 7009: The authorization server responds with HTTP status code 200 if the token
	// has been revoked successfully or if the client submitted an invalid token.
	w.WriteHeader(http.StatusOK)
}

// Helper methods

// AuthorizationSession represents a stored authorization session
type AuthorizationSession struct {
	Request   models.AuthorizationRequest `json:"request"`
	Client    *models.DynamicClient       `json:"client"`
	CreatedAt time.Time                   `json:"created_at"`
}

// redirectError redirects with OAuth2 error parameters
func (h *OAuthHandler) redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, errorCode, errorDescription string) {
	if redirectURI == "" {
		h.writeJSONError(w, http.StatusBadRequest, errorCode, errorDescription)
		return
	}

	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		h.writeJSONError(w, http.StatusBadRequest, models.ErrorInvalidRedirectURI, "Invalid redirect URI")
		return
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

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
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
func (h *OAuthHandler) generateSessionKey() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", errors.Wrapf(err, "failed to generate random session key")
	}
	return base64.URLEncoding.EncodeToString(b), nil
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
		Code:                code,
		ClientID:            session.Client.ClientID,
		CodeChallenge:       session.Request.CodeChallenge,
		CodeChallengeMethod: session.Request.CodeChallengeMethod,
		RedirectURI:         session.Request.RedirectURI,
		Scope:               session.Request.Scope,
		EntraToken:          entraToken,
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}

	if err := h.sessionStore.Set("auth_code_"+code, codeData, 10*time.Minute); err != nil {
		return "", fmt.Errorf("failed to store authorization code: %w", err)
	}

	return code, nil
}

// AuthorizationCodeData represents stored authorization code data
type AuthorizationCodeData struct {
	Code                string        `json:"code"`
	CodeChallenge       string        `json:"code_challenge"`
	CodeChallengeMethod string        `json:"code_challenge_method"`
	ClientID            string        `json:"client_id"`
	RedirectURI         string        `json:"redirect_uri"`
	Scope               string        `json:"scope"`
	EntraToken          *oauth2.Token `json:"entra_token"`
	CreatedAt           time.Time     `json:"created_at"`
	ExpiresAt           time.Time     `json:"expires_at"`
	Used                bool          `json:"used"`
}

// handleAuthorizationCodeGrant handles authorization code grant flow
func (h *OAuthHandler) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request, req *models.TokenRequest, client *models.DynamicClient) {
	// Retrieve authorization code data
	originalCodeData, err := h.getAuthorizationCodeData(req.Code)
	if err != nil {
		h.logger.Warn().Err(err).Str("client_id", req.ClientID).Msg("Invalid authorization code")
		h.writeJSONError(w, http.StatusBadRequest, models.ErrorInvalidGrant, "Invalid authorization code")
		return
	}

	// Validate code hasn't been used and hasn't expired
	if originalCodeData.Used || time.Now().After(originalCodeData.ExpiresAt) {
		h.logger.LogSecurityEvent("expired_or_used_auth_code", getClientIP(r), getUserAgent(r), "high", map[string]interface{}{
			"client_id": req.ClientID,
			"code":      req.Code[:10] + "...",
		})
		h.writeJSONError(w, http.StatusBadRequest, models.ErrorInvalidGrant, "Authorization code expired or already used")
		return
	}

	// Validate client and redirect URI
	if originalCodeData.ClientID != req.ClientID {
		h.logger.LogSecurityEvent("client_mismatch_auth_code", getClientIP(r), getUserAgent(r), "high", map[string]interface{}{
			"expected_client": originalCodeData.ClientID,
			"provided_client": req.ClientID,
		})
		h.writeJSONError(w, http.StatusBadRequest, models.ErrorInvalidGrant, "Client mismatch")
		return
	}

	if originalCodeData.RedirectURI != req.RedirectURI {
		h.writeJSONError(w, http.StatusBadRequest, models.ErrorInvalidGrant, "Redirect URI mismatch")
		return
	}

	// Verify PKCE if required
	if req.CodeVerifier != "" {
		h.logger.Info().
			Str("client_id", req.ClientID).
			Msg("Verifying PKCE CodeChallenge")

		err = h.pkceManager.VerifyAndConsumeChallenge(
			req.ClientID,
			req.CodeVerifier,
			originalCodeData.CodeChallenge,
			originalCodeData.CodeChallengeMethod,
		)
		if err != nil {
			h.logger.LogSecurityEvent("client_failed_challange", getClientIP(r), getUserAgent(r), "high", nil)
			h.writeJSONError(w, http.StatusBadRequest, models.ErrorInvalidGrant, "PKCE failed")
			return
		}
	}

	// Atomically mark code as used to prevent race conditions
	usedCodeData := *originalCodeData // Create a copy
	usedCodeData.Used = true

	// Use CompareAndSet to atomically check and mark the code as used
	success, err := h.sessionStore.CompareAndSet("auth_code_"+req.Code, originalCodeData, &usedCodeData, time.Minute)
	if err != nil {
		h.logger.Error().Err(err).Str("client_id", req.ClientID).Msg("Failed to update authorization code")
		h.writeJSONError(w, http.StatusInternalServerError, models.ErrorServerError, "Internal server error")
		return
	}

	if !success {
		// Another request already used this code
		h.logger.LogSecurityEvent("concurrent_auth_code_usage", getClientIP(r), getUserAgent(r), "high", map[string]interface{}{
			"client_id": req.ClientID,
			"code":      req.Code[:10] + "...",
		})
		h.writeJSONError(w, http.StatusBadRequest, models.ErrorInvalidGrant, "Authorization code already used")
		return
	}

	// Return the Entra ID token directly
	tokenResponse := &models.TokenResponse{
		AccessToken:  originalCodeData.EntraToken.AccessToken,
		TokenType:    models.TokenTypeBearer,
		ExpiresIn:    int64(time.Until(originalCodeData.EntraToken.Expiry).Seconds()),
		RefreshToken: originalCodeData.EntraToken.RefreshToken,
		Scope:        originalCodeData.Scope,
	}

	h.logger.Info().
		Str("client_id", req.ClientID).
		Bool("has_refresh_token", tokenResponse.RefreshToken != "").
		Int64("expires_in", tokenResponse.ExpiresIn).
		Msg("Access token issued successfully")

	h.writeJSONResponse(w, http.StatusOK, tokenResponse)
}

// handleRefreshTokenGrant handles refresh token grant flow
func (h *OAuthHandler) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, req *models.TokenRequest, client *models.DynamicClient) {
	// For direct Entra ID tokens, we'd need to refresh with Entra ID
	// This is simplified for now

	h.logger.Info().
		Str("client_id", req.ClientID).
		Msg("Refresh token grant requested")

	// In a real implementation, you'd:
	// 1. Validate the refresh token
	// 2. Call Entra ID to refresh the token
	// 3. Return the new tokens

	h.writeJSONError(w, http.StatusNotImplemented, models.ErrorUnsupportedGrantType, "Refresh token grant not implemented yet")
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

// HTTP utility functions for standard library conversion

// writeJSONResponse writes a JSON response with the given status code
func (h *OAuthHandler) writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	return json.NewEncoder(w).Encode(data)
}

// writeJSONError writes a JSON error response
func (h *OAuthHandler) writeJSONError(w http.ResponseWriter, statusCode int, errorCode, errorDescription string) error {
	return h.writeJSONResponse(w, statusCode, models.NewOAuth2Error(errorCode, errorDescription))
}

// getClientIP extracts the client IP address from the request
func getClientIP(r *http.Request) string {
	// Check for X-Forwarded-For header (load balancer/proxy)
	if xForwardedFor := r.Header.Get("X-Forwarded-For"); xForwardedFor != "" {
		// Take the first IP in the list
		if firstIP := strings.Split(xForwardedFor, ",")[0]; firstIP != "" {
			return strings.TrimSpace(firstIP)
		}
	}

	// Check for X-Real-IP header (reverse proxy)
	if xRealIP := r.Header.Get("X-Real-IP"); xRealIP != "" {
		return xRealIP
	}

	// Fall back to remote address
	return strings.Split(r.RemoteAddr, ":")[0]
}

// getUserAgent extracts the User-Agent from the request
func getUserAgent(r *http.Request) string {
	return r.Header.Get("User-Agent")
}

// parseJSONBody parses JSON request body into the given struct
func parseJSONBody(r *http.Request, target interface{}) error {
	decoder := json.NewDecoder(r.Body)
	return decoder.Decode(target)
}
