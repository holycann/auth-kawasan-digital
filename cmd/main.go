package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/holycann/auth-kawasan-digital/configs"
	"github.com/holycann/auth-kawasan-digital/internal/auth"
	"github.com/holycann/auth-kawasan-digital/internal/middleware"
	"github.com/holycann/auth-kawasan-digital/internal/routes"
	"github.com/holycann/auth-kawasan-digital/pkg/logger"
	"github.com/holycann/auth-kawasan-digital/pkg/metrics"
	"github.com/holycann/auth-kawasan-digital/pkg/response"
	"github.com/holycann/auth-kawasan-digital/pkg/supabase"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ApplicationDependencies holds all the initialized dependencies
type ApplicationDependencies struct {
	Config         *configs.Config
	Logger         *logger.Logger
	SupabaseAuth   *supabase.SupabaseAuth
	JWKS           *keyfunc.JWKS
	RateLimiter    *middleware.RateLimiter
	JWTMiddleware  *middleware.Middleware
	Router         *gin.Engine
	AuthRepository *auth.SupabaseAuthRepository
	AuthService    *auth.AuthService
	AuthHandler    *auth.AuthHandler
}

func main() {
	// Initialize application context
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		select {
		case <-ctx.Done():
		default:
		}
	}()

	// Initialize dependencies
	deps, err := initializeDependencies()
	if err != nil {
		fmt.Printf("Failed to initialize dependencies: %v\n", err)
		os.Exit(1)
	}
	defer cleanupDependencies(deps)

	// Setup routes
	setupRoutes(deps)

	// Start server
	server := createHTTPServer(deps)

	// Graceful server startup and shutdown
	go startServer(server, deps.Logger, deps.Config)

	// Wait for shutdown signal
	waitForShutdown(server, deps.Logger, deps.Config)
}

// initializeDependencies sets up all application dependencies
func initializeDependencies() (*ApplicationDependencies, error) {
	// Load configuration
	cfg, err := configs.LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	// Initialize logging
	appLogger := initializeLogger(cfg)

	// Initialize Supabase authentication
	supabaseAuth := initializeSupabaseAuth(cfg, appLogger)

	// Initialize JWKS
	jwks := initializeJWKS(cfg, appLogger)

	// Initialize rate limiter
	rateLimiter := initializeRateLimiter()

	// Initialize JWT middleware
	jwtMiddleware := initializeJWTMiddleware(supabaseAuth, jwks, appLogger)

	// Setup Gin router
	router := initializeRouter(appLogger, cfg)

	// Initialize authentication dependencies
	authRepo := auth.NewSupabaseAuthRepository(supabaseAuth, appLogger)
	authService := auth.NewAuthService(authRepo, appLogger)
	authHandler := auth.NewAuthHandler(cfg, authService, appLogger)

	return &ApplicationDependencies{
		Config:         cfg,
		Logger:         appLogger,
		SupabaseAuth:   supabaseAuth,
		JWKS:           jwks,
		RateLimiter:    rateLimiter,
		JWTMiddleware:  jwtMiddleware,
		Router:         router,
		AuthRepository: authRepo,
		AuthService:    authService,
		AuthHandler:    authHandler,
	}, nil
}

// cleanupDependencies performs cleanup for all initialized dependencies
func cleanupDependencies(deps *ApplicationDependencies) {
	// Close logger
	if err := deps.Logger.Close(); err != nil {
		fmt.Printf("Error closing logger: %v\n", err)
	}

	// Additional cleanup can be added here
}

// setupRoutes configures all application routes
func setupRoutes(deps *ApplicationDependencies) {
	// Setup global error handler
	deps.Router.NoRoute(func(c *gin.Context) {
		response.NotFound(c, "route_not_found", "Endpoint not found", c.Request.URL.Path)
	})

	// Setup API routes
	v1Group := deps.Router.Group("/api/v1")
	{
		// Health check endpoint
		v1Group.GET("/health", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"status": "healthy",
				"uptime": time.Since(time.Now()).String(),
			})
		})

		// Prometheus Metrics Endpoint
		v1Group.GET("/metrics", gin.WrapH(promhttp.Handler()))

		routes.AuthRoutes(
			v1Group,
			deps.JWTMiddleware,
			deps.RateLimiter,
			deps.AuthHandler,
		)
	}
}

// createHTTPServer creates and configures the HTTP server
func createHTTPServer(deps *ApplicationDependencies) *http.Server {
	return &http.Server{
		Addr:         fmt.Sprintf("%s:%d", deps.Config.Server.Host, deps.Config.Server.Port),
		Handler:      deps.Router,
		ReadTimeout:  time.Duration(deps.Config.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(deps.Config.Server.WriteTimeout) * time.Second,
	}
}

// startServer handles the server startup process
func startServer(server *http.Server, log *logger.Logger, cfg *configs.Config) {
	log.Info("Starting server",
		"host", cfg.Server.Host,
		"port", cfg.Server.Port,
	)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error("Server startup failed", "error", err)
		os.Exit(1)
	}
}

// waitForShutdown handles graceful shutdown of the server
func waitForShutdown(server *http.Server, log *logger.Logger, cfg *configs.Config) {
	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down server...")

	shutdownCtx, shutdownCancel := context.WithTimeout(
		context.Background(),
		time.Duration(cfg.Server.ShutdownTimeout)*time.Second,
	)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Error("Server shutdown failed", "error", err)
	}

	log.Info("Server exited")
}

// initializeLogger sets up the application logger
func initializeLogger(cfg *configs.Config) *logger.Logger {
	loggerConfig := logger.LoggerConfig{
		Path:        cfg.Logging.FilePath,
		Level:       logger.InfoLevel,
		Development: cfg.Environment == "development",
		MaxSize:     cfg.Logging.MaxSize,
		MaxBackups:  cfg.Logging.MaxBackups,
		MaxAge:      cfg.Logging.MaxAge,
		Compress:    cfg.Logging.Compress,
	}

	return logger.NewLogger(loggerConfig)
}

// initializeSupabaseAuth sets up Supabase authentication client
func initializeSupabaseAuth(cfg *configs.Config, log *logger.Logger) *supabase.SupabaseAuth {
	supabaseConfig := supabase.SupabaseAuthConfig{
		ApiKey:    cfg.Supabase.ApiSecretKey,
		ProjectID: cfg.Supabase.ProjectID,
	}

	supabaseAuth := supabase.NewSupabaseAuth(supabaseConfig)
	log.Info("Supabase authentication initialized")
	return supabaseAuth
}

// initializeJWKS retrieves JWKS keys for JWT validation
func initializeJWKS(cfg *configs.Config, log *logger.Logger) *keyfunc.JWKS {
	jwksURL := fmt.Sprintf("https://%s.supabase.co/auth/v1/.well-known/jwks.json", cfg.Supabase.ProjectID)

	jwks, err := keyfunc.Get(jwksURL, keyfunc.Options{
		RefreshUnknownKID: true,
		RefreshErrorHandler: func(err error) {
			log.Error("JWKS refresh error", "error", err)
		},
	})

	if err != nil {
		log.Error("Failed to retrieve JWKS keys", "error", err)
		os.Exit(1)
	}

	log.Info("JWKS keys initialized successfully")
	return jwks
}

// initializeRateLimiter sets up the rate limiter middleware
func initializeRateLimiter() *middleware.RateLimiter {
	return middleware.NewRateLimiter(middleware.DefaultRateLimiterConfig())
}

// initializeJWTMiddleware creates JWT authentication middleware
func initializeJWTMiddleware(
	supabaseAuth *supabase.SupabaseAuth,
	jwks *keyfunc.JWKS,
	log *logger.Logger,
) *middleware.Middleware {
	return middleware.NewMiddleware(
		supabaseAuth.GetClient(),
		jwks,
		log,
	)
}

// initializeRouter sets up the Gin router with global middleware
func initializeRouter(log *logger.Logger, cfg *configs.Config) *gin.Engine {
	// Set Gin mode based on environment
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	router := gin.New()

	// Global middleware
	router.Use(gin.Recovery())

	// CORS Middleware
	if cfg.CORS.CORSEnabled {
		if cfg.Environment != "production" {
			cfg.CORS.MaxAge = 0
		}

		corsConfig := cors.Config{
			AllowOrigins:     cfg.CORS.AllowedOrigins,
			AllowMethods:     cfg.CORS.AllowedMethods,
			AllowHeaders:     cfg.CORS.AllowedHeaders,
			ExposeHeaders:    cfg.CORS.ExposedHeaders,
			AllowCredentials: cfg.CORS.AllowCredentials,
			MaxAge:           time.Duration(cfg.CORS.MaxAge) * time.Second,
		}

		router.Use(cors.New(corsConfig))
	} else {
		router.Use(cors.New(cors.DefaultConfig()))
	}

	// Prometheus Middleware
	router.Use(func(c *gin.Context) {
		start := time.Now()
		c.Next()

		// Record request metrics
		status := fmt.Sprintf("%d", c.Writer.Status())
		metrics.HTTPRequestsTotal.WithLabelValues(c.Request.Method, c.Request.URL.Path, status).Inc()

		// Record request duration
		duration := time.Since(start).Seconds()
		metrics.HTTPRequestDuration.WithLabelValues(c.Request.Method, c.Request.URL.Path, status).Observe(duration)
	})

	// Logging middleware
	router.Use(func(c *gin.Context) {
		start := time.Now()
		c.Next()

		log.Info("Request processed",
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", c.Writer.Status(),
			"latency", time.Since(start),
		)
	})

	return router
}
