package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ron96g/mcp-utils/pkg/config"
	"github.com/ron96g/mcp-utils/pkg/log"
	"github.com/ron96g/mcp-utils/pkg/models"

	"github.com/gofiber/fiber/v2"
)

// DiscoveryHandler handles OAuth2 discovery endpoints
type DiscoveryHandler struct {
	config *config.Config
	logger *log.Logger
}

// NewDiscoveryHandler creates a new discovery handler
func NewDiscoveryHandler(cfg *config.Config) *DiscoveryHandler {
	return &DiscoveryHandler{
		config: cfg,
		logger: log.WithComponent("discovery_handler"),
	}
}

// RegisterRoutes registers discovery endpoints with the Fiber app
func (h *DiscoveryHandler) RegisterRoutes(app *fiber.App) {
	// OAuth 2.0 Authorization Server Metadata (RFC 8414)
	app.Get("/.well-known/oauth-authorization-server", h.AuthorizationServerMetadata)

	// OAuth 2.0 Protected Resource Metadata (RFC 9728)
	app.Get("/.well-known/oauth-protected-resource", h.ProtectedResourceMetadata)

	// OpenID Connect Discovery (if we add OIDC support later)
	app.Get("/.well-known/openid_configuration", h.OpenIDConfiguration)
}

// AuthorizationServerMetadata returns OAuth 2.0 Authorization Server Metadata (RFC 8414)
func (h *DiscoveryHandler) AuthorizationServerMetadata(c *fiber.Ctx) error {
	h.logger.Debug().
		Str("user_agent", c.Get("User-Agent")).
		Str("client_ip", c.IP()).
		Msg("Authorization server metadata requested")

	baseURL := h.config.GetOAuthIssuerURL()

	metadata := models.AuthorizationServerMetadata{
		Issuer:                baseURL,
		AuthorizationEndpoint: baseURL + "/oauth2/authorize",
		TokenEndpoint:         baseURL + "/oauth2/token",
		RegistrationEndpoint:  baseURL + "/oauth2/register",

		// Supported response types
		ResponseTypesSupported: []string{
			models.ResponseTypeCode,
		},

		// Supported grant types
		GrantTypesSupported: []string{
			models.GrantTypeAuthorizationCode,
			models.GrantTypeRefreshToken,
		},

		// Supported authentication methods
		TokenEndpointAuthMethodsSupported: []string{
			"none",                // Public clients
			"client_secret_basic", // Basic auth
			"client_secret_post",  // Form post
		},

		// PKCE support
		CodeChallengeMethodsSupported: []string{
			models.CodeChallengeMethodS256,
		},

		// Supported scopes
		ScopesSupported: []string{
			models.ScopeOpenID,
			models.ScopeProfile,
			models.ScopeEmail,
			models.ScopeMCP,
		},

		// Additional endpoints
		RevocationEndpoint:    baseURL + "/oauth2/revoke",
		IntrospectionEndpoint: baseURL + "/oauth2/introspect",

		// Documentation
		ServiceDocumentation: baseURL + "/docs",

		// Note: We accept RFC 8707 resource parameters but handle them internally
		// since Microsoft Entra ID doesn't support them directly
	}

	// Set response headers
	c.Set("Content-Type", "application/json")
	c.Set("Cache-Control", "public, max-age=3600") // Cache for 1 hour

	return c.JSON(metadata)
}

// ProtectedResourceMetadata returns OAuth 2.0 Protected Resource Metadata (RFC 9728)
func (h *DiscoveryHandler) ProtectedResourceMetadata(c *fiber.Ctx) error {
	h.logger.Debug().
		Str("user_agent", c.Get("User-Agent")).
		Str("client_ip", c.IP()).
		Msg("Protected resource metadata requested")

	baseURL := h.config.GetOAuthIssuerURL()

	metadata := models.ProtectedResourceMetadata{
		Resource: baseURL,
		AuthorizationServers: []string{
			baseURL,
		},
		BearerMethodsSupported: []string{
			"header", // Authorization: Bearer <token>
			"body",   // Form parameter
		},
		ResourceDocumentation: baseURL + "/docs",
	}

	// Set response headers
	c.Set("Content-Type", "application/json")
	c.Set("Cache-Control", "public, max-age=3600") // Cache for 1 hour

	return c.JSON(metadata)
}

// OpenIDConfiguration returns OpenID Connect Discovery metadata
func (h *DiscoveryHandler) OpenIDConfiguration(c *fiber.Ctx) error {
	h.logger.Debug().
		Str("user_agent", c.Get("User-Agent")).
		Str("client_ip", c.IP()).
		Msg("OpenID Connect configuration requested")

	baseURL := h.config.GetOAuthIssuerURL()

	// Basic OIDC configuration (we can expand this if we add full OIDC support)
	config := map[string]interface{}{
		"issuer":                 baseURL,
		"authorization_endpoint": baseURL + "/oauth2/authorize",
		"token_endpoint":         baseURL + "/oauth2/token",
		"userinfo_endpoint":      baseURL + "/oauth2/userinfo",
		"jwks_uri":               baseURL + "/oauth2/jwks",

		"scopes_supported": []string{
			models.ScopeOpenID,
			models.ScopeProfile,
			models.ScopeEmail,
		},

		"response_types_supported": []string{
			models.ResponseTypeCode,
		},

		"subject_types_supported": []string{
			"public",
		},

		"id_token_signing_alg_values_supported": []string{
			"RS256",
		},

		"token_endpoint_auth_methods_supported": []string{
			"none",
			"client_secret_basic",
			"client_secret_post",
		},

		"code_challenge_methods_supported": []string{
			models.CodeChallengeMethodS256,
		},
	}

	// Set response headers
	c.Set("Content-Type", "application/json")
	c.Set("Cache-Control", "public, max-age=3600") // Cache for 1 hour

	return c.JSON(config)
}

// Handle401Response sends a proper WWW-Authenticate header for 401 responses (RFC 9728)
func (h *DiscoveryHandler) Handle401Response(c *fiber.Ctx, realm, errorCode, errorDescription string) error {
	if realm == "" {
		realm = h.config.GetOAuthIssuerURL()
	}

	// Build WWW-Authenticate header per RFC 9728 Section 5.1
	authHeader := fmt.Sprintf("Bearer realm=\"%s\"", realm)
	authHeader += fmt.Sprintf(", as_uri=\"%s/.well-known/oauth-authorization-server\"", h.config.GetOAuthIssuerURL())

	if errorCode != "" {
		authHeader += fmt.Sprintf(", error=\"%s\"", errorCode)
	}

	if errorDescription != "" {
		authHeader += fmt.Sprintf(", error_description=\"%s\"", errorDescription)
	}

	c.Set("WWW-Authenticate", authHeader)
	c.Set("Content-Type", "application/json")

	errorResponse := models.NewOAuth2Error(errorCode, errorDescription)

	h.logger.Debug().
		Str("error_code", errorCode).
		Str("error_description", errorDescription).
		Str("realm", realm).
		Msg("Sending 401 Unauthorized response")

	return c.Status(fiber.StatusUnauthorized).JSON(errorResponse)
}

type contextKey string

const (
	SubjectKey contextKey = "subject"
	NameKey    contextKey = "name"
	EmailKey   contextKey = "email"
)

// AuthMiddleware creates a middleware for protecting endpoints
func (h *DiscoveryHandler) AuthMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")

		if authHeader == "" {
			return h.Handle401Response(c, "", "invalid_request", "Missing Authorization header")
		}

		// Extract Bearer token
		const bearerPrefix = "Bearer "
		if len(authHeader) <= len(bearerPrefix) || authHeader[:len(bearerPrefix)] != bearerPrefix {
			return h.Handle401Response(c, "", "invalid_request", "Invalid Authorization header format")
		}

		token := authHeader[len(bearerPrefix):]
		if token == "" {
			return h.Handle401Response(c, "", "invalid_token", "Missing access token")
		}

		claims, err := parseAccessToken(token, h.config.EntraID.Audience)
		if err != nil {
			h.logger.Warn().
				Err(err).
				Str("token", token).
				Msg("Failed to parse access token")
			// Return 401 with WWW-Authenticate header
			return h.Handle401Response(c, "", "invalid_token", "Invalid access token")
		}

		// Store token in context for use by handlers
		c.Locals("access_token", token)

		ctx := context.WithValue(c.Context(), SubjectKey, claims.Subject)
		ctx = context.WithValue(ctx, NameKey, claims.Name)
		ctx = context.WithValue(ctx, EmailKey, claims.Email)
		c.SetUserContext(ctx)
		c.Context()

		return c.Next()
	}
}

type AccessTokenClaims struct {
	Subject string `json:"sub"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Aud     string `json:"aud"` // audience
	Iss     string `json:"iss"` // issuer
	Exp     int64  `json:"exp"` // expiration
}

func parseAccessToken(tokenString, expectedAud string) (*AccessTokenClaims, error) {
	// Split JWT into parts
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	// Decode payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %v", err)
	}

	var claims AccessTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %v", err)
	}

	// Basic validation
	if expectedAud != "" && claims.Aud != expectedAud {
		return nil, fmt.Errorf("invalid audience")
	}

	return &claims, nil
}
