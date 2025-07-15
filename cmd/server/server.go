package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ron96g/mcp-utils/pkg/auth"
	"github.com/ron96g/mcp-utils/pkg/config"
	"github.com/ron96g/mcp-utils/pkg/handlers"
	"github.com/ron96g/mcp-utils/pkg/log"
	"github.com/ron96g/mcp-utils/pkg/storage"

	"github.com/gorilla/mux"
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
	router := mux.NewRouter()

	// Initialize handlers
	discoveryHandler := handlers.NewDiscoveryHandler(cfg)
	oauthHandler := handlers.NewOAuthHandler(cfg, clientRegistry, pkceManager, sessionStore)
	mcpHandler := handlers.NewMCPHandler()

	// Register middleware
	registerMiddleware(router, logger)

	// Register routes
	registerRoutes(router, discoveryHandler, oauthHandler, mcpHandler)

	// Create HTTP server
	server := &http.Server{
		Addr:         cfg.GetServerAddress(),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Start server
	return startServer(server, cfg, logger)
}

// createErrorHandler creates a custom error handler for HTTP
func createErrorHandler(logger *log.Logger) func(http.ResponseWriter, *http.Request, int, error) {
	return func(w http.ResponseWriter, r *http.Request, statusCode int, err error) {
		// Log the error
		logger.Error().
			Err(err).
			Int("status_code", statusCode).
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Str("client_ip", r.RemoteAddr).
			Str("user_agent", r.UserAgent()).
			Msg("Request error")

		// Set content type and return error response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		fmt.Fprintf(w, `{"error": true, "message": "%s"}`, err.Error())
	}
}

// registerMiddleware registers global middleware
func registerMiddleware(router *mux.Router, logger *log.Logger) {
	// Create middleware chain
	router.Use(securityMiddleware)
	router.Use(recoveryMiddleware)
	router.Use(loggingMiddleware(logger))
	router.Use(compressionMiddleware)
}

// securityMiddleware adds security headers
func securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;")
		next.ServeHTTP(w, r)
	})
}

// recoveryMiddleware recovers from panics
func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.L.Error().Interface("panic", err).Msg("Panic recovered")
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// loggingMiddleware logs requests
func loggingMiddleware(logger *log.Logger) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Create a response writer wrapper to capture status code
			rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			next.ServeHTTP(rw, r)

			logger.LogRequest(
				r.Method,
				r.URL.Path,
				r.RemoteAddr,
				r.UserAgent(),
				rw.statusCode,
				time.Since(start),
			)
		})
	}
}

// compressionMiddleware handles compression (simplified)
func compressionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// For now, just pass through - you could add gzip compression here
		next.ServeHTTP(w, r)
	})
}

// registerRoutes registers all application routes
func registerRoutes(router *mux.Router, discoveryHandler *handlers.DiscoveryHandler, oauthHandler *handlers.OAuthHandler, mcpHandler *handlers.MCPHandler) {
	// Register discovery routes
	discoveryHandler.RegisterRoutes(router)

	// Register OAuth2 routes
	oauthHandler.RegisterRoutes(router)

	// Protected MCP endpoints
	mcpRouter := router.PathPrefix("/mcp").Subrouter()
	mcpRouter.Use(discoveryHandler.AuthMiddleware()) // Protect MCP endpoints
	mcpHandler.RegisterRoutes(mcpRouter)
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
