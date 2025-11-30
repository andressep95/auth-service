package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"

	"github.com/andressep95/auth-service/internal/config"
	"github.com/andressep95/auth-service/internal/handler"
	"github.com/andressep95/auth-service/internal/handler/middleware"
	"github.com/andressep95/auth-service/internal/repository/postgres"
	"github.com/andressep95/auth-service/internal/service"
	"github.com/andressep95/auth-service/pkg/jwt"
	"github.com/andressep95/auth-service/pkg/validator"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize database connection
	db, err := initDB(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("Error closing database connection: %v", err)
		}
	}()
	log.Println("✓ Database connection established")

	// Initialize Redis client
	redisClient, err := initRedis(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize Redis: %v", err)
	}
	defer func() {
		if err := redisClient.Close(); err != nil {
			log.Printf("Error closing Redis connection: %v", err)
		}
	}()
	log.Println("✓ Redis connection established")

	// Load RSA keys for JWT
	privateKey, publicKey, err := loadRSAKeys(cfg)
	if err != nil {
		log.Fatalf("Failed to load RSA keys: %v", err)
	}
	log.Println("✓ RSA keys loaded successfully")

	// Initialize validator
	validate := validator.NewValidator()

	// Initialize repositories
	userRepo := postgres.NewUserRepository(db)
	sessionRepo := postgres.NewSessionRepository(db)
	roleRepo := postgres.NewRoleRepository(db)

	// Initialize JWT token service
	tokenService, err := jwt.NewTokenService(
		privateKey,
		publicKey,
		cfg.JWT.AccessTokenExpiry,
		cfg.JWT.RefreshTokenExpiry,
		cfg.JWT.Issuer,
	)
	if err != nil {
		log.Fatalf("Failed to initialize token service: %v", err)
	}

	// Initialize services
	authService := service.NewAuthService(userRepo, sessionRepo, tokenService, cfg)
	userService := service.NewUserService(userRepo)
	roleService := service.NewRoleService(roleRepo, userRepo)

	// Initialize handlers
	authHandler := handler.NewAuthHandler(authService, validate)
	userHandler := handler.NewUserHandler(userService, validate)
	roleHandler := handler.NewRoleHandler(roleService, validate)
	healthHandler := handler.NewHealthHandler()

	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName:               "Auth Service v1.0",
		DisableStartupMessage: false,
		ErrorHandler:          customErrorHandler,
		ReadTimeout:           cfg.Server.ReadTimeout,
		WriteTimeout:          cfg.Server.WriteTimeout,
	})

	// Setup global middlewares
	app.Use(middleware.RecoveryMiddleware())
	app.Use(middleware.LoggerMiddleware())
	app.Use(middleware.CORSMiddleware())

	// Setup authorization middlewares
	authMiddleware := middleware.AuthMiddleware(tokenService)
	requireAdmin := middleware.RequireAdmin(roleService)
	requireModerator := middleware.RequireModerator(roleService)

	// Setup routes
	handler.SetupRoutes(
		app,
		authHandler,
		userHandler,
		roleHandler,
		healthHandler,
		authMiddleware,
		requireAdmin,
		requireModerator,
	)

	// Graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// Start server in goroutine
	go func() {
		addr := fmt.Sprintf(":%s", cfg.Server.Port)
		log.Printf("🚀 Server starting on http://localhost%s", addr)
		log.Printf("📝 Environment: %s", cfg.Server.Environment)
		if err := app.Listen(addr); err != nil {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	// Wait for interrupt signal
	<-ctx.Done()
	log.Println("⏳ Shutting down server gracefully...")

	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Shutdown server
	if err := app.ShutdownWithContext(shutdownCtx); err != nil {
		log.Printf("❌ Server forced to shutdown: %v", err)
	}

	log.Println("✓ Server stopped")
}

// initDB initializes PostgreSQL database connection with retry logic
func initDB(cfg *config.Config) (*sqlx.DB, error) {
	dsn := cfg.Database.DSN()

	var db *sqlx.DB
	var err error

	maxRetries := 5
	retryInterval := 2 * time.Second

	for i := 0; i < maxRetries; i++ {
		db, err = sqlx.Connect("postgres", dsn)
		if err == nil {
			break
		}

		log.Printf("Failed to connect to database (attempt %d/%d): %v", i+1, maxRetries, err)
		if i < maxRetries-1 {
			time.Sleep(retryInterval)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to database after %d attempts: %w", maxRetries, err)
	}

	// Set connection pool settings
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return db, nil
}

// initRedis initializes Redis client and verifies connection
func initRedis(cfg *config.Config) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:         cfg.Redis.Addr(),
		Password:     cfg.Redis.Password,
		DB:           cfg.Redis.DB,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		PoolSize:     10,
		MinIdleConns: 5,
	})

	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to ping Redis: %w", err)
	}

	return client, nil
}

// loadRSAKeys loads RSA private and public keys from files
func loadRSAKeys(cfg *config.Config) ([]byte, []byte, error) {
	// Load private key
	privateKey, err := os.ReadFile(cfg.JWT.PrivateKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	// Load public key
	publicKey, err := os.ReadFile(cfg.JWT.PublicKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	if len(privateKey) == 0 {
		return nil, nil, fmt.Errorf("private key file is empty")
	}

	if len(publicKey) == 0 {
		return nil, nil, fmt.Errorf("public key file is empty")
	}

	return privateKey, publicKey, nil
}

// customErrorHandler handles Fiber errors
func customErrorHandler(c *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError

	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
	}

	return c.Status(code).JSON(fiber.Map{
		"error":   true,
		"message": err.Error(),
	})
}
