package config

import "github.com/spf13/viper"

func setDefaults() {
	// Server defaults
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("server.trusted_proxies", []string{})
	viper.SetDefault("server.read_timeout", "30s")
	viper.SetDefault("server.write_timeout", "30s")
	viper.SetDefault("server.idle_timeout", "120s")

	// Entra ID defaults
	viper.SetDefault("entra_id.authority", "https://login.microsoftonline.com")
	viper.SetDefault("entra_id.scopes", []string{"openid", "profile", "email"})

	// OAuth defaults
	viper.SetDefault("oauth.token_lifetime", "1h")
	viper.SetDefault("oauth.refresh_token_lifetime", "24h")
	viper.SetDefault("oauth.code_lifetime", "10m")
	viper.SetDefault("oauth.require_pkce", true)
	viper.SetDefault("oauth.allowed_origins", []string{"http://localhost:*"})

	// Logging defaults
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")
	viper.SetDefault("logging.output", "stderr")

	// Storage defaults
	viper.SetDefault("storage.type", "memory")
	viper.SetDefault("storage.ttl", "1h")
	viper.SetDefault("storage.redis.address", "localhost:6379")
	viper.SetDefault("storage.redis.db", 0)
	viper.SetDefault("storage.redis.max_retries", 3)
	viper.SetDefault("storage.redis.dial_timeout", "5s")
	viper.SetDefault("storage.postgres.host", "localhost")
	viper.SetDefault("storage.postgres.port", 5432)
	viper.SetDefault("storage.postgres.ssl_mode", "prefer")
}
