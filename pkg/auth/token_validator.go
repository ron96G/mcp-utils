package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ron96g/mcp-utils/pkg/log"
	"github.com/ron96g/mcp-utils/pkg/models"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
)

type TokenValidator interface {
	ValidateToken(tokenString string) (*ValidationResult, error)
	ValidateTokenWithRequiredScopes(tokenString string, requiredScopes []string) (*ValidationResult, error)
	ValidateTokenWithRequiredRoles(tokenString string, requiredRoles []string) (*ValidationResult, error)
}

var _ TokenValidator = (*DefaultTokenValidator)(nil)

// TokenValidator handles JWT token validation with JWKS support
type DefaultTokenValidator struct {
	tenantID string
	audience string
	issuer   string
	jwks     *keyfunc.JWKS
	logger   *log.Logger
}

// TokenValidatorConfig holds configuration for token validation
type TokenValidatorConfig struct {
	TenantID        string        `yaml:"tenant_id"`
	Issuer          string        `yaml:"issuer"`
	Audience        string        `yaml:"audience"`
	RefreshInterval time.Duration `yaml:"refresh_interval"`
	RefreshTimeout  time.Duration `yaml:"refresh_timeout"`
	RateLimit       time.Duration `yaml:"rate_limit"`
}

// DefaultTokenValidatorConfig returns sensible defaults
func DefaultTokenValidatorConfig() *TokenValidatorConfig {
	return &TokenValidatorConfig{
		RefreshInterval: time.Hour,
		RefreshTimeout:  10 * time.Second,
		RateLimit:       5 * time.Minute,
	}
}

// NewTokenValidator creates a new JWT token validator
func NewTokenValidator(config *TokenValidatorConfig) (TokenValidator, error) {
	if config == nil {
		config = DefaultTokenValidatorConfig()
	}

	validator := &DefaultTokenValidator{
		tenantID: config.TenantID,
		audience: config.Audience,
		issuer:   config.Issuer,
		logger:   log.WithComponent("token_validator"),
	}

	// Initialize JWKS
	if err := validator.initJWKS(config); err != nil {
		return nil, fmt.Errorf("failed to initialize JWKS: %w", err)
	}

	return validator, nil
}

// initJWKS sets up JWKS fetching and caching for Entra ID
func (v *DefaultTokenValidator) initJWKS(config *TokenValidatorConfig) error {
	// Construct Entra ID JWKS endpoint
	jwksURL := fmt.Sprintf("https://login.microsoftonline.com/%s/discovery/v2.0/keys", config.TenantID)

	// Configure JWKS options
	options := keyfunc.Options{
		Ctx:                 context.Background(),
		RefreshErrorHandler: v.jwksErrorHandler,
		RefreshInterval:     config.RefreshInterval,
		RefreshRateLimit:    config.RateLimit,
		RefreshTimeout:      config.RefreshTimeout,
		RefreshUnknownKID:   true, // Refresh when encountering unknown key ID
	}

	// Create JWKS instance
	jwks, err := keyfunc.Get(jwksURL, options)
	if err != nil {
		return fmt.Errorf("failed to create JWKS from URL %s: %w", jwksURL, err)
	}

	v.jwks = jwks

	v.logger.Info().
		Str("jwks_url", jwksURL).
		Dur("refresh_interval", config.RefreshInterval).
		Msg("JWKS initialized successfully")

	return nil
}

// jwksErrorHandler handles JWKS refresh errors
func (v *DefaultTokenValidator) jwksErrorHandler(err error) {
	v.logger.Error().
		Err(err).
		Msg("Failed to refresh JWKS")

	// Log as security event since JWKS failures could indicate attacks
	v.logger.LogSecurityEvent("jwks_refresh_failed", "", "", "medium", map[string]interface{}{
		"error": err.Error(),
	})
}

// ValidationResult contains the result of token validation
type ValidationResult struct {
	Valid  bool                      `json:"valid"`
	Claims *models.AccessTokenClaims `json:"claims,omitempty"`
	Error  string                    `json:"error,omitempty"`
	Scopes []string                  `json:"scopes,omitempty"`
	Roles  []string                  `json:"roles,omitempty"`
}

// ValidateToken validates and parses a JWT access token
func (v *DefaultTokenValidator) ValidateToken(tokenString string) (*ValidationResult, error) {
	if tokenString == "" {
		return &ValidationResult{
			Valid: false,
			Error: "empty token",
		}, nil
	}

	// Parse and validate the JWT token
	token, err := jwt.ParseWithClaims(
		tokenString,
		&models.AccessTokenClaims{},
		v.jwks.Keyfunc,
		jwt.WithValidMethods([]string{"RS256"}), // Only allow RS256
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
		jwt.WithLeeway(30*time.Second), // Allow 30 second clock skew
	)

	if err != nil {
		v.logger.LogSecurityEvent("jwt_parse_failed", "", "", "high", map[string]interface{}{
			"error": err.Error(),
		})
		return &ValidationResult{
			Valid: false,
			Error: fmt.Sprintf("JWT validation failed: %v", err),
		}, nil
	}

	// Verify token is valid
	if !token.Valid {
		v.logger.LogSecurityEvent("jwt_invalid", "", "", "high", map[string]interface{}{
			"reason": "token not valid",
		})
		return &ValidationResult{
			Valid: false,
			Error: "invalid JWT token",
		}, nil
	}

	// Extract claims
	claims, ok := token.Claims.(*models.AccessTokenClaims)
	if !ok {
		return &ValidationResult{
			Valid: false,
			Error: "invalid token claims type",
		}, nil
	}

	// Additional validation
	if err := v.validateClaims(claims); err != nil {
		return &ValidationResult{
			Valid: false,
			Error: fmt.Sprintf("claims validation failed: %v", err),
		}, nil
	}

	// Return successful validation result
	return &ValidationResult{
		Valid:  true,
		Claims: claims,
		Scopes: claims.GetScopes(),
		Roles:  claims.Roles,
	}, nil
}

// validateClaims performs additional business logic validation
func (v *DefaultTokenValidator) validateClaims(claims *models.AccessTokenClaims) error {
	// Validate tenant ID matches configuration
	if claims.TenantID != v.tenantID {
		v.logger.LogSecurityEvent("invalid_tenant_id", "", "", "high", map[string]interface{}{
			"expected_tenant": v.tenantID,
			"actual_tenant":   claims.TenantID,
		})
		return fmt.Errorf("invalid tenant ID")
	}

	// Validate required claims are present
	if claims.Subject == "" {
		return fmt.Errorf("missing subject claim")
	}

	if claims.ObjectID == "" {
		return fmt.Errorf("missing object ID claim")
	}

	// Validate token has required scope for MCP access
	if !claims.HasScope("mcp.read") && !claims.HasScope("mcp.write") {
		v.logger.LogSecurityEvent("insufficient_scope", "", "", "medium", map[string]interface{}{
			"required_scope": "mcp.access",
			"actual_scopes":  claims.GetScopes(),
			"subject":        claims.Subject,
		})
		return fmt.Errorf("insufficient scope for MCP access")
	}

	// Additional security validations
	now := time.Now()

	// Check if token was issued in the future (clock skew protection)
	if claims.IssuedAt != nil && claims.IssuedAt.After(now.Add(5*time.Minute)) {
		v.logger.LogSecurityEvent("token_issued_future", "", "", "high", map[string]interface{}{
			"issued_at":    claims.IssuedAt,
			"current_time": now,
		})
		return fmt.Errorf("token issued in the future")
	}

	// Check authentication time if present (for sensitive operations)
	if claims.AuthTime > 0 {
		authTime := time.Unix(claims.AuthTime, 0)
		if now.Sub(authTime) > 24*time.Hour {
			v.logger.LogSecurityEvent("old_authentication", "", "", "low", map[string]interface{}{
				"auth_time": authTime,
				"age_hours": now.Sub(authTime).Hours(),
			})
			// Don't fail, just log for monitoring
		}
	}

	return nil
}

// ValidateTokenWithRequiredScopes validates a token and checks for specific scopes
func (v *DefaultTokenValidator) ValidateTokenWithRequiredScopes(tokenString string, requiredScopes []string) (*ValidationResult, error) {
	result, err := v.ValidateToken(tokenString)
	if err != nil || !result.Valid {
		return result, err
	}

	// Check required scopes
	for _, requiredScope := range requiredScopes {
		if !result.Claims.HasScope(requiredScope) {
			v.logger.LogSecurityEvent("missing_required_scope", "", "", "medium", map[string]interface{}{
				"required_scope": requiredScope,
				"actual_scopes":  result.Claims.GetScopes(),
				"subject":        result.Claims.Subject,
			})
			return &ValidationResult{
				Valid: false,
				Error: fmt.Sprintf("missing required scope: %s", requiredScope),
			}, nil
		}
	}

	return result, nil
}

// ValidateTokenWithRequiredRoles validates a token and checks for specific roles
func (v *DefaultTokenValidator) ValidateTokenWithRequiredRoles(tokenString string, requiredRoles []string) (*ValidationResult, error) {
	result, err := v.ValidateToken(tokenString)
	if err != nil || !result.Valid {
		return result, err
	}

	// Check required roles
	for _, requiredRole := range requiredRoles {
		if !result.Claims.HasRole(requiredRole) {
			v.logger.LogSecurityEvent("missing_required_role", "", "", "medium", map[string]interface{}{
				"required_role": requiredRole,
				"actual_roles":  result.Claims.Roles,
				"subject":       result.Claims.Subject,
			})
			return &ValidationResult{
				Valid: false,
				Error: fmt.Sprintf("missing required role: %s", requiredRole),
			}, nil
		}
	}

	return result, nil
}

// Close cleans up resources used by the token validator
func (v *DefaultTokenValidator) Close() error {
	if v.jwks != nil {
		v.jwks.EndBackground()
	}
	return nil
}

// ExtractTokenFromAuthHeader extracts Bearer token from Authorization header
func ExtractTokenFromAuthHeader(authHeader string) (string, error) {
	if authHeader == "" {
		return "", fmt.Errorf("missing Authorization header")
	}

	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) || len(authHeader) <= len(bearerPrefix) {
		return "", fmt.Errorf("invalid Authorization header format")
	}

	token := strings.TrimSpace(authHeader[len(bearerPrefix):])
	if token == "" {
		return "", fmt.Errorf("empty bearer token")
	}

	return token, nil
}
