package models

import (
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// OAuth2 Grant Types
const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"
	GrantTypeClientCredentials = "client_credentials"
)

// OAuth2 Response Types
const (
	ResponseTypeCode = "code"
)

// PKCE Code Challenge Methods
const (
	CodeChallengeMethodPlain = "plain"
	CodeChallengeMethodS256  = "S256"
)

// OAuth2 Token Types
const (
	TokenTypeBearer = "Bearer"
)

// OAuth2 Scopes
const (
	ScopeOpenID  = "openid"
	ScopeProfile = "profile"
	ScopeEmail   = "email"
	ScopeMCP     = "mcp.access"
)

// Dynamic Client Registration Models

// ClientRegistrationRequest represents a dynamic client registration request (RFC 7591)
type ClientRegistrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris,omitempty" validate:"required,min=1,dive,url"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty" validate:"omitempty,oneof=none client_secret_basic client_secret_post"`
	GrantTypes              []string `json:"grant_types,omitempty" validate:"omitempty,dive,oneof=authorization_code refresh_token"`
	ResponseTypes           []string `json:"response_types,omitempty" validate:"omitempty,dive,oneof=code"`
	ClientName              string   `json:"client_name,omitempty" validate:"omitempty,max=100"`
	ClientURI               string   `json:"client_uri,omitempty" validate:"omitempty,url"`
	LogoURI                 string   `json:"logo_uri,omitempty" validate:"omitempty,url"`
	Scope                   string   `json:"scope,omitempty"`
	Contacts                []string `json:"contacts,omitempty" validate:"omitempty,dive,email"`
	TOSUri                  string   `json:"tos_uri,omitempty" validate:"omitempty,url"`
	PolicyURI               string   `json:"policy_uri,omitempty" validate:"omitempty,url"`
	JWKSUri                 string   `json:"jwks_uri,omitempty" validate:"omitempty,url"`
	SoftwareID              string   `json:"software_id,omitempty"`
	SoftwareVersion         string   `json:"software_version,omitempty"`
	InitialAccessToken      string   `json:"initial_access_token,omitempty"`
}

// ClientRegistrationResponse represents a dynamic client registration response (RFC 7591)
type ClientRegistrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
	TOSUri                  string   `json:"tos_uri,omitempty"`
	PolicyURI               string   `json:"policy_uri,omitempty"`
	JWKSUri                 string   `json:"jwks_uri,omitempty"`
	SoftwareID              string   `json:"software_id,omitempty"`
	SoftwareVersion         string   `json:"software_version,omitempty"`
}

// DynamicClient represents a dynamically registered OAuth2 client
type DynamicClient struct {
	ID                      string    `json:"id" db:"id"`
	ClientID                string    `json:"client_id" db:"client_id"`
	ClientSecret            string    `json:"client_secret,omitempty" db:"client_secret"`
	ClientName              string    `json:"client_name,omitempty" db:"client_name"`
	ClientURI               string    `json:"client_uri,omitempty" db:"client_uri"`
	LogoURI                 string    `json:"logo_uri,omitempty" db:"logo_uri"`
	RedirectURIs            []string  `json:"redirect_uris" db:"redirect_uris"`
	GrantTypes              []string  `json:"grant_types" db:"grant_types"`
	ResponseTypes           []string  `json:"response_types" db:"response_types"`
	Scope                   string    `json:"scope,omitempty" db:"scope"`
	TokenEndpointAuthMethod string    `json:"token_endpoint_auth_method" db:"token_endpoint_auth_method"`
	Contacts                []string  `json:"contacts,omitempty" db:"contacts"`
	TOSUri                  string    `json:"tos_uri,omitempty" db:"tos_uri"`
	PolicyURI               string    `json:"policy_uri,omitempty" db:"policy_uri"`
	JWKSUri                 string    `json:"jwks_uri,omitempty" db:"jwks_uri"`
	SoftwareID              string    `json:"software_id,omitempty" db:"software_id"`
	SoftwareVersion         string    `json:"software_version,omitempty" db:"software_version"`
	CreatedAt               time.Time `json:"client_id_issued_at" db:"created_at"`
	UpdatedAt               time.Time `json:"updated_at" db:"updated_at"`
	IsActive                bool      `json:"is_active" db:"is_active"`
}

// IsPublicClient returns true if this is a public client (no client secret)
func (c *DynamicClient) IsPublicClient() bool {
	return c.TokenEndpointAuthMethod == "none" || c.ClientSecret == ""
}

// SupportsGrantType checks if the client supports a specific grant type
func (c *DynamicClient) SupportsGrantType(grantType string) bool {
	for _, gt := range c.GrantTypes {
		if gt == grantType {
			return true
		}
	}
	return false
}

// SupportsResponseType checks if the client supports a specific response type
func (c *DynamicClient) SupportsResponseType(responseType string) bool {
	for _, rt := range c.ResponseTypes {
		if rt == responseType {
			return true
		}
	}
	return false
}

// IsRedirectURIAllowed checks if a redirect URI is allowed for this client
func (c *DynamicClient) IsRedirectURIAllowed(redirectURI string) bool {
	for _, uri := range c.RedirectURIs {
		if uri == redirectURI {
			return true
		}
	}
	return false
}

// SetClientSecret hashes and sets the client secret
func (c *DynamicClient) SetClientSecret(secret string) error {
	hashedSecret, err := HashClientSecret(secret)
	if err != nil {
		return err
	}
	c.ClientSecret = hashedSecret
	return nil
}

// VerifyClientSecret verifies a plain text secret against the stored hash
func (c *DynamicClient) VerifyClientSecret(secret string) bool {
	return VerifyClientSecret(secret, c.ClientSecret)
}

// Access Token Models

// AccessTokenClaims represents validated JWT claims from Entra ID
type AccessTokenClaims struct {
	jwt.RegisteredClaims

	// Standard OIDC claims
	Name              string `json:"name,omitempty"`
	Email             string `json:"email,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`

	// Azure AD specific claims
	TenantID         string `json:"tid,omitempty"`
	ObjectID         string `json:"oid,omitempty"`
	AppID            string `json:"appid,omitempty"`
	AppDisplayName   string `json:"app_displayname,omitempty"`
	IdentityProvider string `json:"idp,omitempty"`

	// Scopes and roles
	Scope  string   `json:"scp,omitempty"` // Space-separated scopes
	Roles  []string `json:"roles,omitempty"`
	Groups []string `json:"groups,omitempty"`

	// Additional security claims
	AuthenticationMethodsReferences []string `json:"amr,omitempty"`
	AuthTime                        int64    `json:"auth_time,omitempty"`

	// Application permissions
	ApplicationPermissions []string `json:"app_perms,omitempty"`
}

// GetScopes returns scopes as a slice
func (c *AccessTokenClaims) GetScopes() []string {
	if c.Scope == "" {
		return nil
	}
	return strings.Fields(c.Scope)
}

// HasScope checks if the token has a specific scope
func (c *AccessTokenClaims) HasScope(scope string) bool {
	scopes := c.GetScopes()
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// HasRole checks if the token has a specific role
func (c *AccessTokenClaims) HasRole(role string) bool {
	for _, r := range c.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// GetEmailAddress returns the best available email address from claims
func (c *AccessTokenClaims) GetEmailAddress() string {
	if c.Email != "" {
		return c.Email
	}
	if c.PreferredUsername != "" && strings.Contains(c.PreferredUsername, "@") {
		return c.PreferredUsername
	}
	return ""
}

// OAuth2 Flow Models

// AuthorizationRequest represents an OAuth2 authorization request
type AuthorizationRequest struct {
	ResponseType        string `form:"response_type" json:"response_type" validate:"required,eq=code"`
	ClientID            string `form:"client_id" json:"client_id" validate:"required"`
	RedirectURI         string `form:"redirect_uri" json:"redirect_uri" validate:"required,url"`
	Scope               string `form:"scope" json:"scope"`
	State               string `form:"state" json:"state" validate:"required"`
	CodeChallenge       string `form:"code_challenge" json:"code_challenge"`
	CodeChallengeMethod string `form:"code_challenge_method" json:"code_challenge_method" validate:"omitempty,oneof=plain S256"`
	Resource            string `form:"resource" json:"resource"` // RFC 8707 - Resource Indicators
	Nonce               string `form:"nonce" json:"nonce"`
	Prompt              string `form:"prompt" json:"prompt"`
	MaxAge              int    `form:"max_age" json:"max_age"`
	UILocales           string `form:"ui_locales" json:"ui_locales"`
	IDTokenHint         string `form:"id_token_hint" json:"id_token_hint"`
	LoginHint           string `form:"login_hint" json:"login_hint"`
	ACRValues           string `form:"acr_values" json:"acr_values"`
}

// RequiresPKCE returns true if this request requires PKCE validation
func (ar *AuthorizationRequest) RequiresPKCE() bool {
	return ar.CodeChallenge != "" && ar.CodeChallengeMethod != ""
}

// AuthorizationResponse represents an OAuth2 authorization response
type AuthorizationResponse struct {
	Code             string `json:"code,omitempty"`
	State            string `json:"state,omitempty"`
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

// TokenRequest represents an OAuth2 token request
type TokenRequest struct {
	GrantType    string `form:"grant_type" json:"grant_type" validate:"required,oneof=authorization_code refresh_token client_credentials"`
	Code         string `form:"code" json:"code"`
	RedirectURI  string `form:"redirect_uri" json:"redirect_uri"`
	ClientID     string `form:"client_id" json:"client_id" validate:"required"`
	ClientSecret string `form:"client_secret" json:"client_secret"`
	RefreshToken string `form:"refresh_token" json:"refresh_token"`
	Scope        string `form:"scope" json:"scope"`
	CodeVerifier string `form:"code_verifier" json:"code_verifier"`
	Resource     string `form:"resource" json:"resource"` // RFC 8707
}

// TokenResponse represents an OAuth2 token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Resource     string `json:"resource,omitempty"`
}

// TokenErrorResponse represents an OAuth2 token error response
type TokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

// PKCE Models

// PKCEChallenge represents a PKCE challenge for authorization code flow
type PKCEChallenge struct {
	ID                  string    `json:"id" db:"id"`
	ClientID            string    `json:"client_id" db:"client_id"`
	CodeChallenge       string    `json:"code_challenge" db:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method" db:"code_challenge_method"`
	CreatedAt           time.Time `json:"created_at" db:"created_at"`
	ExpiresAt           time.Time `json:"expires_at" db:"expires_at"`
	Used                bool      `json:"used" db:"used"`
}

// IsExpired returns true if the PKCE challenge has expired
func (p *PKCEChallenge) IsExpired() bool {
	return time.Now().After(p.ExpiresAt)
}

// Discovery Models (RFC 8414, RFC 9728)

// AuthorizationServerMetadata represents OAuth 2.0 Authorization Server Metadata (RFC 8414)
type AuthorizationServerMetadata struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	JWKSUri                                    string   `json:"jwks_uri,omitempty"`
	RegistrationEndpoint                       string   `json:"registration_endpoint,omitempty"`
	ScopesSupported                            []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	ServiceDocumentation                       string   `json:"service_documentation,omitempty"`
	UILocalesSupported                         []string `json:"ui_locales_supported,omitempty"`
	OpPolicyURI                                string   `json:"op_policy_uri,omitempty"`
	OpTosURI                                   string   `json:"op_tos_uri,omitempty"`
	RevocationEndpoint                         string   `json:"revocation_endpoint,omitempty"`
	IntrospectionEndpoint                      string   `json:"introspection_endpoint,omitempty"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported,omitempty"`
}

// ProtectedResourceMetadata represents OAuth 2.0 Protected Resource Metadata (RFC 9728)
type ProtectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	JWKSUri                string   `json:"jwks_uri,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
	ResourceDocumentation  string   `json:"resource_documentation,omitempty"`
	ResourcePolicyURI      string   `json:"resource_policy_uri,omitempty"`
	ResourceTosURI         string   `json:"resource_tos_uri,omitempty"`
}

// Error Models

// OAuth2Error represents a standard OAuth2 error
type OAuth2Error struct {
	Err              string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
	State            string `json:"state,omitempty"`
}

// Standard OAuth2 error codes
const (
	ErrorInvalidRequest          = "invalid_request"
	ErrorUnauthorizedClient      = "unauthorized_client"
	ErrorAccessDenied            = "access_denied"
	ErrorUnsupportedResponseType = "unsupported_response_type"
	ErrorInvalidScope            = "invalid_scope"
	ErrorServerError             = "server_error"
	ErrorTemporarilyUnavailable  = "temporarily_unavailable"
	ErrorInvalidClient           = "invalid_client"
	ErrorInvalidGrant            = "invalid_grant"
	ErrorUnsupportedGrantType    = "unsupported_grant_type"
	ErrorInvalidRedirectURI      = "invalid_redirect_uri"
	ErrorInvalidClientMetadata   = "invalid_client_metadata"
)

// NewOAuth2Error creates a new OAuth2Error
func NewOAuth2Error(code, description string) *OAuth2Error {
	return &OAuth2Error{
		Err:              code,
		ErrorDescription: description,
	}
}

// Error implements the error interface
func (e *OAuth2Error) Error() string {
	if e.ErrorDescription != "" {
		return e.Err + ": " + e.ErrorDescription
	}
	return e.Err
}

// Session Models

// AuthSession represents an authorization session
type AuthSession struct {
	ID                  string                 `json:"id" db:"id"`
	State               string                 `json:"state" db:"state"`
	ClientID            string                 `json:"client_id" db:"client_id"`
	RedirectURI         string                 `json:"redirect_uri" db:"redirect_uri"`
	Scope               string                 `json:"scope" db:"scope"`
	Resource            string                 `json:"resource" db:"resource"`
	CodeChallenge       string                 `json:"code_challenge" db:"code_challenge"`
	CodeChallengeMethod string                 `json:"code_challenge_method" db:"code_challenge_method"`
	Nonce               string                 `json:"nonce" db:"nonce"`
	EntraIDState        string                 `json:"entra_id_state" db:"entra_id_state"`
	AdditionalData      map[string]interface{} `json:"additional_data" db:"additional_data"`
	CreatedAt           time.Time              `json:"created_at" db:"created_at"`
	ExpiresAt           time.Time              `json:"expires_at" db:"expires_at"`
	Used                bool                   `json:"used" db:"used"`
}

// IsExpired returns true if the auth session has expired
func (as *AuthSession) IsExpired() bool {
	return time.Now().After(as.ExpiresAt)
}
