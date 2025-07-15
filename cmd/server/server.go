package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/ron96g/mcp-utils/pkg/auth"
	"github.com/ron96g/mcp-utils/pkg/config"
	"github.com/ron96g/mcp-utils/pkg/handlers"
	"github.com/ron96g/mcp-utils/pkg/log"
	"github.com/ron96g/mcp-utils/pkg/storage"
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

	// Create router
	router := chi.NewRouter()

	// Initialize handlers
	discoveryHandler := handlers.NewDiscoveryHandler(cfg)
	oauthHandler := handlers.NewOAuthHandler(cfg, clientRegistry, pkceManager, sessionStore)
	mcpHandler := handlers.NewMCPHandler()

	// Register middleware
	registerMiddleware(router)

	// Register routes
	registerRoutes(router, discoveryHandler, oauthHandler, mcpHandler)

	// Create HTTP server
	server := &http.Server{
		Addr:           cfg.GetServerAddress(),
		Handler:        router,
		ReadTimeout:    cfg.Server.ReadTimeout,
		WriteTimeout:   cfg.Server.WriteTimeout,
		IdleTimeout:    cfg.Server.IdleTimeout,
		MaxHeaderBytes: 1 << 20, // 1 MB
	}

	// Start server
	return startServer(server, cfg, logger)
}

// registerMiddleware registers global middleware
func registerMiddleware(router chi.Router) {
	// Create middleware chain
	router.Use(securityMiddleware)
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	router.Use(middleware.Compress(5))
}

// securityMiddleware adds security headers
func securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;")
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
		next.ServeHTTP(w, r)
	})
}

// registerRoutes registers all application routes
func registerRoutes(router chi.Router, discoveryHandler *handlers.DiscoveryHandler, oauthHandler *handlers.OAuthHandler, mcpHandler *handlers.MCPHandler) {
	// Register discovery routes
	discoveryHandler.RegisterRoutes(router)

	// Register OAuth2 routes
	oauthHandler.RegisterRoutes(router)

	// Protected MCP endpoints
	router.Group(func(mcpRouter chi.Router) {
		mcpRouter.Use(discoveryHandler.AuthMiddleware()) // Protect MCP endpoints
		mcpHandler.RegisterRoutes(mcpRouter)

	})
}

func startServer(server *http.Server, cfg *config.Config, logger *log.Logger) error {
	// Create a channel to listen for interrupt signals
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Start server in a goroutine
	go func() {
		var err error

		if cfg.IsTLSEnabled() {
			logger.Info().
				Str("address", server.Addr).
				Str("cert_file", cfg.Server.TLSCertFile).
				Str("key_file", cfg.Server.TLSKeyFile).
				Msg("Starting HTTPS server")

			err = server.ListenAndServeTLS(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
		} else {
			logger.Info().
				Str("address", server.Addr).
				Msg("Starting HTTP server")

			err = server.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
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
	if err := server.Shutdown(ctx); err != nil {
		logger.Error().Err(err).Msg("Server forced to shutdown")
		return err
	}

	logger.Info().Msg("Server shutdown complete")
	return nil
}
