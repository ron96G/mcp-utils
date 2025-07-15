package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/ron96g/mcp-utils/pkg/auth"
	"github.com/ron96g/mcp-utils/pkg/config"
	"github.com/ron96g/mcp-utils/pkg/log"
	"github.com/ron96g/mcp-utils/pkg/models"
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
		Issuer:   cfg.GetEntraIDIssuer(),
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

// RegisterRoutes registers discovery endpoints with the router
func (h *DiscoveryHandler) RegisterRoutes(router chi.Router) {
	// OAuth 2.0 Authorization Server Metadata (RFC 8414)
	router.Get("/.well-known/oauth-authorization-server", h.AuthorizationServerMetadata)

	// OAuth 2.0 Protected Resource Metadata (RFC 9728)
	router.Get("/.well-known/oauth-protected-resource", h.ProtectedResourceMetadata)

	// OpenID Connect Discovery (if we add OIDC support later)
	router.Get("/.well-known/openid_configuration", h.OpenIDConfiguration)
}

// AuthorizationServerMetadata returns OAuth 2.0 Authorization Server Metadata (RFC 8414)
func (h *DiscoveryHandler) AuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug().
		Str("user_agent", r.UserAgent()).
		Str("client_ip", r.RemoteAddr).
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
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600") // Cache for 1 hour

	json.NewEncoder(w).Encode(metadata)
}

// ProtectedResourceMetadata returns OAuth 2.0 Protected Resource Metadata (RFC 9728)
func (h *DiscoveryHandler) ProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug().
		Str("user_agent", r.UserAgent()).
		Str("client_ip", r.RemoteAddr).
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
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600") // Cache for 1 hour

	json.NewEncoder(w).Encode(metadata)
}

// OpenIDConfiguration returns OpenID Connect Discovery metadata
func (h *DiscoveryHandler) OpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug().
		Str("user_agent", r.UserAgent()).
		Str("client_ip", r.RemoteAddr).
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
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600") // Cache for 1 hour

	json.NewEncoder(w).Encode(config)
}

// Handle401Response sends a proper WWW-Authenticate header for 401 responses (RFC 9728)
func (h *DiscoveryHandler) Handle401Response(w http.ResponseWriter, r *http.Request, realm, errorCode, errorDescription string) {
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

	w.Header().Set("WWW-Authenticate", authHeader)
	w.Header().Set("Content-Type", "application/json")

	errorResponse := models.NewOAuth2Error(errorCode, errorDescription)

	h.logger.Debug().
		Str("error_code", errorCode).
		Str("error_description", errorDescription).
		Str("realm", realm).
		Msg("Sending 401 Unauthorized response")

	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(errorResponse)
}

type ContextKey string

const (
	ContextKeyClaims      ContextKey = "claims"
	ContextKeyAccessToken ContextKey = "access_token"
	ContextKeyTokenScopes ContextKey = "token_scopes"
	ContextKeyTokenRoles  ContextKey = "token_roles"
	ContextKeySubject     ContextKey = "subject"
	ContextKeyName        ContextKey = "name"
	ContextKeyEmail       ContextKey = "email"
)

// AuthMiddleware creates a middleware for protecting endpoints
func (h *DiscoveryHandler) AuthMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				h.Handle401Response(w, r, "", "invalid_request", "Missing Authorization header")
				return
			}

			// Extract token from header
			token, err := auth.ExtractTokenFromAuthHeader(authHeader)
			if err != nil {
				h.Handle401Response(w, r, "", "invalid_request", err.Error())
				return
			}

			// Validate token
			result, err := h.tokenValidator.ValidateToken(token)
			if err != nil {
				h.logger.Error().
					Err(err).
					Str("client_ip", r.RemoteAddr).
					Str("user_agent", r.UserAgent()).
					Msg("Token validation error")
				h.Handle401Response(w, r, "", "server_error", "Internal server error")
				return
			}

			if !result.Valid {
				h.logger.Warn().
					Str("error", result.Error).
					Str("client_ip", r.RemoteAddr).
					Str("user_agent", r.UserAgent()).
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

				h.Handle401Response(w, r, "", errorCode, result.Error)
				return
			}

			// Set user context for easy access
			ctx := context.WithValue(r.Context(), ContextKeySubject, result.Claims.Subject)
			ctx = context.WithValue(ctx, ContextKeyName, result.Claims.Name)
			ctx = context.WithValue(ctx, ContextKeyEmail, result.Claims.GetEmailAddress())
			ctx = context.WithValue(ctx, ContextKeyAccessToken, token)
			ctx = context.WithValue(ctx, ContextKeyClaims, result.Claims)
			ctx = context.WithValue(ctx, ContextKeyTokenScopes, result.Scopes)
			ctx = context.WithValue(ctx, ContextKeyTokenRoles, result.Roles)

			h.logger.Debug().
				Str("subject", result.Claims.Subject).
				Str("name", result.Claims.Name).
				Str("email", result.Claims.GetEmailAddress()).
				Strs("scopes", result.Scopes).
				Strs("roles", result.Roles).
				Msg("Token validated successfully")

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
