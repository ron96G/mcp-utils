package handlers

import (
	"context"
	"fmt"
	"strings"

	"github.com/ron96g/mcp-utils/pkg/auth"
	"github.com/ron96g/mcp-utils/pkg/config"
	"github.com/ron96g/mcp-utils/pkg/log"
	"github.com/ron96g/mcp-utils/pkg/models"

	"github.com/gofiber/fiber/v2"
)

// DiscoveryHandler handles OAuth2 discovery endpoints
type DiscoveryHandler struct {
	config         *config.Config
	logger         *log.Logger
	tokenValidator auth.TokenValidator
}

// NewDiscoveryHandler creates a new discovery handler
func NewDiscoveryHandler(cfg *config.Config) *DiscoveryHandler {
	validatorConfig := &auth.TokenValidatorConfig{
		TenantID: cfg.EntraID.TenantID,
		Audience: cfg.EntraID.Audience,
		Issuer:   cfg.GetEntraIDAuthority(),
	}

	tokenValidator, err := auth.NewTokenValidator(validatorConfig)
	if err != nil {
		log.L.Fatal().Err(err).Msg("Failed to initialize token validator")
	}

	return &DiscoveryHandler{
		config:         cfg,
		logger:         log.WithComponent("discovery_handler"),
		tokenValidator: tokenValidator,
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
		// Extract Authorization header
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return h.Handle401Response(c, "", "invalid_request", "Missing Authorization header")
		}

		// Extract token from header
		token, err := auth.ExtractTokenFromAuthHeader(authHeader)
		if err != nil {
			return h.Handle401Response(c, "", "invalid_request", err.Error())
		}

		// Validate token
		result, err := h.tokenValidator.ValidateToken(token)
		if err != nil {
			h.logger.Error().
				Err(err).
				Str("client_ip", c.IP()).
				Str("user_agent", c.Get("User-Agent")).
				Msg("Token validation error")
			return h.Handle401Response(c, "", "server_error", "Internal server error")
		}

		if !result.Valid {
			h.logger.Warn().
				Str("error", result.Error).
				Str("client_ip", c.IP()).
				Str("user_agent", c.Get("User-Agent")).
				Msg("Token validation failed")

			// Determine appropriate error code based on validation error
			errorCode := "invalid_token"
			if result.Error != "" {
				if strings.Contains(result.Error, "expired") {
					errorCode = "invalid_token"
				} else if strings.Contains(result.Error, "scope") {
					errorCode = "insufficient_scope"
				}
			}

			return h.Handle401Response(c, "", errorCode, result.Error)
		}
		// Store validated data in context
		c.Locals("access_token", token)
		c.Locals("access_token_claims", result.Claims)
		c.Locals("token_scopes", result.Scopes)
		c.Locals("token_roles", result.Roles)

		// Set user context for easy access
		ctx := context.WithValue(c.Context(), SubjectKey, result.Claims.Subject)
		ctx = context.WithValue(ctx, NameKey, result.Claims.Name)
		ctx = context.WithValue(ctx, EmailKey, result.Claims.GetEmailAddress())
		c.SetUserContext(ctx)

		h.logger.Debug().
			Str("subject", result.Claims.Subject).
			Str("name", result.Claims.Name).
			Str("email", result.Claims.GetEmailAddress()).
			Strs("scopes", result.Scopes).
			Strs("roles", result.Roles).
			Msg("Token validated successfully")

		return c.Next()
	}
}
