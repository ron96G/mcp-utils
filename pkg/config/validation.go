package config

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"

	"github.com/go-playground/validator/v10"
)

func formatValidationErrors(err error) error {
	if validationErrors, ok := err.(validator.ValidationErrors); ok {
		var messages []string

		for _, e := range validationErrors {
			field := strings.ToLower(e.Namespace())

			switch e.Tag() {
			case "required":
				messages = append(messages, fmt.Sprintf("%s is required", field))
			case "min":
				messages = append(messages, fmt.Sprintf("%s must be at least %s", field, e.Param()))
			case "max":
				messages = append(messages, fmt.Sprintf("%s must be at most %s", field, e.Param()))
			case "oneof":
				messages = append(messages, fmt.Sprintf("%s must be one of: %s", field, e.Param()))
			case "url":
				messages = append(messages, fmt.Sprintf("%s must be a valid URL", field))
			case "uuid4":
				messages = append(messages, fmt.Sprintf("%s must be a valid UUID", field))
			case "hostname":
				messages = append(messages, fmt.Sprintf("%s must be a valid hostname", field))
			case "ip":
				messages = append(messages, fmt.Sprintf("%s must be a valid IP address", field))
			case "cidr":
				messages = append(messages, fmt.Sprintf("%s must be a valid CIDR notation", field))
			case "file":
				messages = append(messages, fmt.Sprintf("%s must be a valid file path", field))
			default:
				messages = append(messages, fmt.Sprintf("%s failed validation: %s", field, e.Tag()))
			}
		}

		return errors.New(strings.Join(messages, "; "))
	}

	return err
}

func validateCustomRules(config *Config) error {
	var errs []string

	// TLS configuration validation
	if (config.Server.TLSCertFile != "") != (config.Server.TLSKeyFile != "") {
		errs = append(errs, "both tls_cert_file and tls_key_file must be specified together")
	}

	// OAuth issuer and base URL consistency
	if config.OAuth.Issuer != config.OAuth.BaseURL {
		// This is a warning rather than an error, but you might want to enforce consistency
		errs = append(errs, "oauth.issuer should typically match oauth.base_url")
	}

	// Ensure refresh token lifetime is longer than access token lifetime
	if config.OAuth.RefreshTokenLifetime <= config.OAuth.TokenLifetime {
		errs = append(errs, "refresh_token_lifetime must be longer than token_lifetime")
	}

	// Validate Entra ID redirect URI matches server configuration
	if config.EntraID.RedirectURI != "" && config.OAuth.BaseURL != "" {
		expectedCallback := config.OAuth.BaseURL + "/oauth2/callback"
		if config.EntraID.RedirectURI != expectedCallback {
			errs = append(errs, fmt.Sprintf("entra_id.redirect_uri should be %s to match oauth.base_url", expectedCallback))
		}
	}

	// Storage-specific validations
	switch config.Storage.Type {
	case "redis":
		if config.Storage.Redis.Address == "" {
			errs = append(errs, "redis address is required when storage type is redis")
		}
	case "postgres":
		if config.Storage.Postgres.Host == "" {
			errs = append(errs, "postgres host is required when storage type is postgres")
		}
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}

	return nil
}

// validateFile checks if a file path exists
func validateFile(fl validator.FieldLevel) bool {
	if fl.Field().String() == "" {
		return true // Empty is allowed for optional fields
	}

	// You could add actual file existence check here
	// _, err := os.Stat(fl.Field().String())
	// return err == nil

	// For now, just check it's not empty
	return fl.Field().String() != ""
}

// validateTLSPair ensures both cert and key are provided together
func validateTLSPair(fl validator.FieldLevel) bool {
	// This would need access to the parent struct to check both fields
	// For now, we handle this in validateCustomRules
	return true
}
