package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ron96g/mcp-utils/pkg/auth"
	"github.com/ron96g/mcp-utils/pkg/config"
	"github.com/ron96g/mcp-utils/pkg/handlers"
	"github.com/ron96g/mcp-utils/pkg/log"
	"github.com/ron96g/mcp-utils/pkg/storage"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

func main() {
	cfg, err := config.LoadConfig("")
	if err != nil {
		panic(err)
	}
	log.Init(cfg.Logging)

	// Initialize components
	initLog := log.WithComponent("init_server")
	if err := initializeServer(cfg, initLog); err != nil {
		initLog.Fatal().Err(err).Msg("Failed to initialize server")
	}
}

// initializeServer initializes and starts the server
func initializeServer(cfg *config.Config, logger *log.Logger) error {
	// Initialize session store
	sessionStoreConfig := &storage.SessionStoreConfig{
		Type:            cfg.Storage.Type,
		DefaultTTL:      cfg.Storage.TTL,
		CleanupInterval: 5 * time.Minute,
	}

	sessionStore, err := storage.NewSessionStore(sessionStoreConfig)
	if err != nil {
		return fmt.Errorf("failed to create session store: %w", err)
	}

	// Initialize client registry
	clientRegistryConfig := auth.DefaultClientRegistryConfig()
	clientRegistryConfig.AllowLocalhostRedirect = true
	clientRegistryConfig.RequireHTTPS = false // Allow HTTP for localhost development

	clientRegistry := auth.NewMemoryClientRegistry(clientRegistryConfig)

	// Initialize PKCE manager
	pkceConfig := auth.DefaultPKCEConfig()
	pkceManager := auth.NewMemoryPKCEManager(pkceConfig)

	// Create Fiber app
	app := createFiberApp(cfg, logger)

	// Initialize handlers
	discoveryHandler := handlers.NewDiscoveryHandler(cfg)
	oauthHandler := handlers.NewOAuthHandler(cfg, clientRegistry, pkceManager, sessionStore)
	mcpHandler := handlers.NewMCPHandler()

	// Register middleware
	registerMiddleware(app, cfg, discoveryHandler)

	// Register routes
	registerRoutes(app, discoveryHandler, oauthHandler, mcpHandler)

	// Start server
	return startServer(app, cfg, logger)
}

// createFiberApp creates and configures the Fiber application
func createFiberApp(cfg *config.Config, logger *log.Logger) *fiber.App {
	// Configure Fiber
	fiberConfig := fiber.Config{
		ServerHeader:          cfg.Logging.ServiceName,
		AppName:               fmt.Sprintf("%s v%s", cfg.Logging.ServiceName, cfg.Logging.ServiceVersion),
		DisableStartupMessage: true,
		ReadTimeout:           cfg.Server.ReadTimeout,
		WriteTimeout:          cfg.Server.WriteTimeout,
		IdleTimeout:           cfg.Server.IdleTimeout,
		ErrorHandler:          createErrorHandler(logger),
	}

	return fiber.New(fiberConfig)
}

// createErrorHandler creates a custom error handler for Fiber
func createErrorHandler(logger *log.Logger) fiber.ErrorHandler {
	return func(c *fiber.Ctx, err error) error {
		// Default 500 status code
		code := fiber.StatusInternalServerError

		// Retrieve the custom status code if it's a *fiber.Error
		var e *fiber.Error
		if errors.As(err, &e) {
			code = e.Code
		}

		// Log the error
		logger.Error().
			Err(err).
			Int("status_code", code).
			Str("method", c.Method()).
			Str("path", c.Path()).
			Str("client_ip", c.IP()).
			Str("user_agent", c.Get("User-Agent")).
			Msg("Request error")

		// Return status code with error message
		return c.Status(code).JSON(fiber.Map{
			"error":   true,
			"message": err.Error(),
		})
	}
}

// registerMiddleware registers global middleware
func registerMiddleware(app *fiber.App, cfg *config.Config, discoveryHandler *handlers.DiscoveryHandler) {
	// Security middleware
	app.Use(helmet.New())

	// Recovery middleware
	app.Use(recover.New())

	// Logger middleware
	app.Use(logger.New()) // TODO: Configure logger middleware

	// Compression middleware
	app.Use(compress.New(compress.Config{
		Level: compress.LevelBestSpeed,
	}))

}

// registerRoutes registers all application routes
func registerRoutes(app *fiber.App, discoveryHandler *handlers.DiscoveryHandler, oauthHandler *handlers.OAuthHandler, mcpHandler *handlers.MCPHandler) {
	// Register discovery routes
	discoveryHandler.RegisterRoutes(app)

	// Register OAuth2 routes
	oauthHandler.RegisterRoutes(app)

	// Protected MCP endpoints
	mcp := app.Group("/mcp")
	mcp.Use(discoveryHandler.AuthMiddleware()) // Protect MCP endpoints
	mcpHandler.RegisterRoutes(mcp)
}

func startServer(app *fiber.App, cfg *config.Config, logger *log.Logger) error {
	// Create a channel to listen for interrupt signals
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Start server in a goroutine
	go func() {
		var err error

		if cfg.IsTLSEnabled() {
			logger.Info().
				Str("address", cfg.GetServerAddress()).
				Str("cert_file", cfg.Server.TLSCertFile).
				Str("key_file", cfg.Server.TLSKeyFile).
				Msg("Starting HTTPS server")

			err = app.ListenTLS(cfg.GetServerAddress(), cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
		} else {
			logger.Info().
				Str("address", cfg.GetServerAddress()).
				Msg("Starting HTTP server")

			err = app.Listen(cfg.GetServerAddress())
		}

		if err != nil {
			logger.Fatal().Err(err).Msg("Failed to start server")
		}
	}()

	// Log server startup
	logger.Info().
		Str("oauth_issuer", cfg.GetOAuthIssuerURL()).
		Str("authorization_endpoint", cfg.GetOAuthIssuerURL()+"/oauth2/authorize").
		Str("token_endpoint", cfg.GetOAuthIssuerURL()+"/oauth2/token").
		Str("registration_endpoint", cfg.GetOAuthIssuerURL()+"/oauth2/register").
		Str("oauth-authorization-server", cfg.GetOAuthIssuerURL()+"/.well-known/oauth-authorization-server").
		Str("oauth-protected-resource", cfg.GetOAuthIssuerURL()+"/.well-known/oauth-protected-resource").
		Str("openid_configuration", cfg.GetOAuthIssuerURL()+"/.well-known/openid_configuration").
		Msg("MCP OAuth2 Server started successfully")

	// Wait for interrupt signal
	sig := <-quit
	logger.Info().Str("signal", sig.String()).Msg("Shutdown signal received")

	// Graceful shutdown
	logger.Info().Msg("Shutting down server...")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown server
	if err := app.ShutdownWithContext(ctx); err != nil {
		logger.Error().Err(err).Msg("Server forced to shutdown")
		return err
	}

	logger.Info().Msg("Server shutdown complete")
	return nil

}
