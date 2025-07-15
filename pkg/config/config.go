package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/spf13/viper"
)

// Config represents the application configuration
type Config struct {
	Server  ServerConfig  `mapstructure:"server" validate:"required"`
	EntraID EntraIDConfig `mapstructure:"entra_id" validate:"required"`
	OAuth   OAuthConfig   `mapstructure:"oauth" validate:"required"`
	Logging LoggingConfig `mapstructure:"logging" validate:"required"`
	Storage StorageConfig `mapstructure:"storage" validate:"required"`
}

type LoggingConfig struct {
	ServiceName    string `mapstructure:"service_name"`
	ServiceVersion string `mapstructure:"service_version"`
	Level          string `mapstructure:"level" validate:"required,oneof=debug info warn error"`
	Output         string `mapstructure:"output" validate:"required,oneof=stdout stderr"`
}

// ServerConfig holds server-related configuration
type ServerConfig struct {
	Port           int           `mapstructure:"port" validate:"required,min=1,max=65535"`
	Host           string        `mapstructure:"host" validate:"required,hostname|ip"`
	TLSCertFile    string        `mapstructure:"tls_cert_file" validate:"omitempty,file"`
	TLSKeyFile     string        `mapstructure:"tls_key_file" validate:"omitempty,file"`
	TrustedProxies []string      `mapstructure:"trusted_proxies" validate:"dive,cidr|ip"`
	ReadTimeout    time.Duration `mapstructure:"read_timeout" validate:"required,min=1s"`
	WriteTimeout   time.Duration `mapstructure:"write_timeout" validate:"required,min=1s"`
	IdleTimeout    time.Duration `mapstructure:"idle_timeout" validate:"required,min=1s"`
}

// EntraIDConfig holds Microsoft Entra ID configuration
type EntraIDConfig struct {
	TenantID     string   `mapstructure:"tenant_id" validate:"required,uuid4"`
	ClientID     string   `mapstructure:"client_id" validate:"required,uuid4"`
	ClientSecret string   `mapstructure:"client_secret" validate:"required,min=20"`
	Issuer       string   `mapstructure:"issuer" validate:"required,url"`
	Scopes       []string `mapstructure:"scopes" validate:"required,min=1,dive,required"`
	RedirectURI  string   `mapstructure:"redirect_uri" validate:"required,url"`
	Audience     string   `mapstructure:"audience"`
}

// OAuthConfig holds OAuth2 server configuration
type OAuthConfig struct {
	Issuer               string        `mapstructure:"issuer" validate:"required,url"`
	BaseURL              string        `mapstructure:"base_url" validate:"required,url"`
	TokenLifetime        time.Duration `mapstructure:"token_lifetime" validate:"required,min=1m,max=24h"`
	RefreshTokenLifetime time.Duration `mapstructure:"refresh_token_lifetime" validate:"required,min=1h,max=168h"`
	CodeLifetime         time.Duration `mapstructure:"code_lifetime" validate:"required,min=1m,max=30m"`
	SigningKey           string        `mapstructure:"signing_key" validate:"required,min=32"`
	RequirePKCE          bool          `mapstructure:"require_pkce"`
	AllowedOrigins       []string      `mapstructure:"allowed_origins" validate:"dive,required"`
}

// StorageConfig holds storage configuration for sessions and tokens
type StorageConfig struct {
	Type     string         `mapstructure:"type" validate:"required,oneof=memory redis postgres"`
	Redis    RedisConfig    `mapstructure:"redis" validate:"required_if=Type redis"`
	Postgres PostgresConfig `mapstructure:"postgres" validate:"required_if=Type postgres"`
	TTL      time.Duration  `mapstructure:"ttl" validate:"required,min=1m"`
}

// RedisConfig holds Redis configuration
type RedisConfig struct {
	Address     string        `mapstructure:"address" validate:"required,hostname_port"`
	Password    string        `mapstructure:"password"`
	DB          int           `mapstructure:"db" validate:"min=0,max=15"`
	MaxRetries  int           `mapstructure:"max_retries" validate:"min=0,max=10"`
	DialTimeout time.Duration `mapstructure:"dial_timeout" validate:"required,min=1s,max=30s"`
}

// PostgresConfig holds PostgreSQL configuration
type PostgresConfig struct {
	Host     string `mapstructure:"host" validate:"required,hostname|ip"`
	Port     int    `mapstructure:"port" validate:"required,min=1,max=65535"`
	User     string `mapstructure:"user" validate:"required,min=1"`
	Password string `mapstructure:"password" validate:"required,min=1"`
	Database string `mapstructure:"database" validate:"required,min=1"`
	SSLMode  string `mapstructure:"ssl_mode" validate:"required,oneof=disable require verify-ca verify-full prefer"`
}

var validate *validator.Validate

func init() {
	validate = validator.New()

	// Register custom validators
	validate.RegisterValidation("file", validateFile)
	validate.RegisterValidation("tls_pair", validateTLSPair)
}

func LoadConfig(configPath string) (*Config, error) {
	// Set default values
	setDefaults()

	// Set config file
	if configPath != "" {
		viper.SetConfigFile(configPath)
	} else {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		viper.AddConfigPath("./configs")
		viper.AddConfigPath("/etc/mcp-server")
		viper.AddConfigPath("$HOME/.mcp-server")
	}

	// Enable environment variable binding
	viper.AutomaticEnv()
	viper.SetEnvPrefix("MCP")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Read config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found, continue with defaults and env vars
	}

	// Unmarshal configuration
	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate configuration using struct tags
	if err := validate.Struct(&config); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", formatValidationErrors(err))
	}

	// Additional custom validations
	if err := validateCustomRules(&config); err != nil {
		return nil, fmt.Errorf("custom validation failed: %w", err)
	}

	return &config, nil
}

// IsTLSEnabled returns true if TLS is configured
func (c *Config) IsTLSEnabled() bool {
	return c.Server.TLSCertFile != "" && c.Server.TLSKeyFile != ""
}

// GetRedisConnectionString returns the Redis connection string for go-redis
func (c *Config) GetRedisConnectionString() string {
	if c.Storage.Redis.Password != "" {
		return fmt.Sprintf("redis://:%s@%s/%d", c.Storage.Redis.Password, c.Storage.Redis.Address, c.Storage.Redis.DB)
	}
	return fmt.Sprintf("redis://%s/%d", c.Storage.Redis.Address, c.Storage.Redis.DB)
}

// GetPostgresConnectionString returns the PostgreSQL connection string
func (c *Config) GetPostgresConnectionString() string {
	connStr := fmt.Sprintf("host=%s port=%d user=%s dbname=%s sslmode=%s",
		c.Storage.Postgres.Host,
		c.Storage.Postgres.Port,
		c.Storage.Postgres.User,
		c.Storage.Postgres.Database,
		c.Storage.Postgres.SSLMode,
	)

	if c.Storage.Postgres.Password != "" {
		connStr += fmt.Sprintf(" password=%s", c.Storage.Postgres.Password)
	}

	return connStr
}

// GetServerAddress returns the server address in host:port format
func (c *Config) GetServerAddress() string {
	return fmt.Sprintf("%s:%d", c.Server.Host, c.Server.Port)
}

// GetEntraIDIssuer returns the complete Entra ID authority URL
func (c *Config) GetEntraIDIssuer() string {
	return c.EntraID.Issuer
}

// GetOAuthCallbackURL returns the OAuth callback URL for this server
func (c *Config) GetOAuthCallbackURL() string {
	return fmt.Sprintf("%s/oauth2/callback", c.OAuth.BaseURL)
}

// GetOAuthIssuerURL returns the OAuth issuer URL
func (c *Config) GetOAuthIssuerURL() string {
	if c.OAuth.Issuer != "" {
		return c.OAuth.Issuer
	}
	return c.OAuth.BaseURL
}
