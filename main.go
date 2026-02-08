package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"adel/config"
	"adel/handlers"
	"adel/middleware"
	"adel/session"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

func main() {
	if err := run(); err != nil {
		slog.Error("application failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	// Load .env file if it exists
	if err := godotenv.Load(); err != nil {
		slog.Info("No .env file found, using environment variables")
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Initialize structured logger based on config
	var logger *slog.Logger
	if cfg.Logging.Format == "json" {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: getLogLevel(cfg.Logging.Level),
		}))
	} else {
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: getLogLevel(cfg.Logging.Level),
		}))
	}
	slog.SetDefault(logger)

	// Enable debug logging if configured
	middleware.SetDebugLogging(cfg.Logging.Debug)
	if cfg.Logging.Debug {
		slog.Info("Debug logging enabled")
	}

	// Create session manager
	sessionMgr := session.NewManager(cfg)
	defer sessionMgr.Stop()

	// Create handler
	handler := handlers.NewHandler(cfg, sessionMgr)

	// Setup router
	router := setupRouter(handler, sessionMgr, cfg)

	// Create server
	server := &http.Server{
		Addr:         ":" + cfg.Server.Port,
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Channel for shutdown signals
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	// Channel for server errors
	serverErrors := make(chan error, 1)

	// Start server in goroutine
	go func() {
		useTLS := cfg.TLS.Enabled && certsExist(cfg.TLS.CertFile, cfg.TLS.KeyFile)

		if useTLS {
			slog.Info("Starting HTTPS server", "port", cfg.Server.Port)
			slog.Info("AD Server configured", "server", cfg.AD.Server, "port", cfg.AD.Port)

			if err := server.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile); !errors.Is(err, http.ErrServerClosed) {
				serverErrors <- fmt.Errorf("failed to start HTTPS server: %w", err)
			}
		} else {
			if cfg.TLS.Enabled {
				slog.Warn("TLS certificates not found, falling back to HTTP")
			}
			slog.Info("Starting HTTP server", "port", cfg.Server.Port)
			slog.Info("AD Server configured", "server", cfg.AD.Server, "port", cfg.AD.Port)

			if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				serverErrors <- fmt.Errorf("failed to start HTTP server: %w", err)
			}
		}
	}()

	// Wait for shutdown signal or server error
	select {
	case err := <-serverErrors:
		return err
	case <-shutdown:
		slog.Info("Shutting down server...")
	}

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown failed: %w", err)
	}

	slog.Info("Server stopped gracefully")
	return nil
}

func setupRouter(handler *handlers.Handler, sessionMgr *session.Manager, cfg *config.Config) *mux.Router {
	router := mux.NewRouter()

	// Enable strict slash to handle trailing slashes correctly
	router.StrictSlash(true)

	// Apply global middleware
	router.Use(middleware.Recovery)
	router.Use(middleware.Logging)
	router.Use(middleware.SecurityHeaders)
	router.Use(middleware.CORS(middleware.CORSConfig{
		AllowedOrigins:   cfg.CORS.AllowedOrigins,
		AllowedMethods:   cfg.CORS.AllowedMethods,
		AllowedHeaders:   cfg.CORS.AllowedHeaders,
		AllowCredentials: cfg.CORS.AllowCredentials,
		MaxAge:           cfg.CORS.MaxAge,
	}))
	router.Use(middleware.JSON)

	// Handle OPTIONS requests globally (for CORS preflight)
	router.Methods(http.MethodOptions).HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CORS middleware already handled the response
	})

	// Health check endpoint (no auth required)
	router.HandleFunc("/health", handler.Health).Methods(http.MethodGet)

	// API v1 routes
	api := router.PathPrefix("/api/v1").Subrouter()

	// Public routes (no session required)
	api.HandleFunc("/login", handler.Login).Methods(http.MethodPost)
	api.HandleFunc("/logout", handler.Logout).Methods(http.MethodPost)
	api.HandleFunc("/session", handler.SessionInfo).Methods(http.MethodGet)

	// Protected routes (session required)
	protected := api.PathPrefix("").Subrouter()
	protected.Use(middleware.RequireSession(sessionMgr))

	// User routes
	protected.HandleFunc("/users/me", handler.GetCurrentUser).Methods(http.MethodGet)
	protected.HandleFunc("/users/{username}", handler.GetUser).Methods(http.MethodGet)
	protected.HandleFunc("/users", handler.EditUser).Methods(http.MethodPut, http.MethodPatch)
	protected.HandleFunc("/users/change-password", handler.ChangeUserPassword).Methods(http.MethodPost)

	// Group routes
	protected.HandleFunc("/groups", handler.GetAllGroups).Methods(http.MethodGet)
	protected.HandleFunc("/groups/add-member", handler.AddUserToGroup).Methods(http.MethodPost)
	protected.HandleFunc("/groups/remove-member", handler.RemoveUserFromGroup).Methods(http.MethodPost, http.MethodDelete)

	// Search route
	protected.HandleFunc("/search", handler.Search).Methods(http.MethodGet, http.MethodPost)

	// Print registered routes
	if cfg.Logging.Debug {
		printRoutes(router)
	}

	return router
}

func printRoutes(router *mux.Router) {
	fmt.Println("\nRegistered routes:")
	fmt.Println("==================")
	_ = router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		path, err := route.GetPathTemplate()
		if err != nil {
			return nil
		}
		methods, err := route.GetMethods()
		if err != nil {
			methods = []string{"ANY"}
		}
		for _, method := range methods {
			fmt.Printf("  %s %s\n", method, path)
		}
		return nil
	})
	fmt.Println()
}

func certsExist(certFile, keyFile string) bool {
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		return false
	}
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		return false
	}
	return true
}

func getLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
