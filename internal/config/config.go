package config

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Redis    RedisConfig
	JWT      JWTConfig
	Auth     AuthConfig
	CORS     CORSConfig
	Email    EmailConfig
}

type ServerConfig struct {
	Port         string
	Environment  string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

type DatabaseConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
	SSLMode  string
}

type RedisConfig struct {
	Host     string
	Port     string
	Password string
	DB       int
}

type JWTConfig struct {
	PrivateKeyPath     string
	PublicKeyPath      string
	AccessTokenExpiry  time.Duration
	RefreshTokenExpiry time.Duration
	Issuer             string
}

type AuthConfig struct {
	MaxFailedLogins int
	LockDuration    time.Duration
	BcryptCost      int
}

type CORSConfig struct {
	AllowedOrigins string
}

type EmailConfig struct {
	Provider        string
	APIKey          string
	FromEmail       string
	FromName        string
	BaseURL         string
	VerificationURL string
	ResetURL        string
	Enabled         bool
}

func Load() (*Config, error) {
	// Intentar cargar .env (opcional en producción)
	_ = godotenv.Load()

	cfg := &Config{
		Server: ServerConfig{
			Port:         getEnv("SERVER_PORT", "8080"),
			Environment:  getEnv("ENVIRONMENT", "development"),
			ReadTimeout:  getDurationEnv("SERVER_READ_TIMEOUT", 10*time.Second),
			WriteTimeout: getDurationEnv("SERVER_WRITE_TIMEOUT", 10*time.Second),
		},
		Database: DatabaseConfig{
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     getEnv("DB_PORT", "5432"),
			User:     getEnv("DB_USER", "auth"),
			Password: getEnv("DB_PASSWORD", "auth"),
			DBName:   getEnv("DB_NAME", "authdb"),
			SSLMode:  getEnv("DB_SSLMODE", "disable"),
		},
		Redis: RedisConfig{
			Host:     getEnv("REDIS_HOST", "localhost"),
			Port:     getEnv("REDIS_PORT", "6379"),
			Password: getEnv("REDIS_PASSWORD", ""),
			DB:       getIntEnv("REDIS_DB", 0),
		},
		JWT: JWTConfig{
			PrivateKeyPath:     getEnv("JWT_PRIVATE_KEY_PATH", "./keys/private.pem"),
			PublicKeyPath:      getEnv("JWT_PUBLIC_KEY_PATH", "./keys/public.pem"),
			AccessTokenExpiry:  getDurationEnv("JWT_ACCESS_EXPIRY", 15*time.Minute),
			RefreshTokenExpiry: getDurationEnv("JWT_REFRESH_EXPIRY", 7*24*time.Hour),
			Issuer:             getEnv("JWT_ISSUER", "auth-service"),
		},
		Auth: AuthConfig{
			MaxFailedLogins: getIntEnv("AUTH_MAX_FAILED_LOGINS", 5),
			LockDuration:    getDurationEnv("AUTH_LOCK_DURATION", 15*time.Minute),
			BcryptCost:      getIntEnv("AUTH_BCRYPT_COST", 12),
		},
		CORS: CORSConfig{
			AllowedOrigins: getEnv("CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8080"),
		},
		Email: EmailConfig{
			Provider:        getEnv("EMAIL_PROVIDER", "resend"),
			APIKey:          getEnv("EMAIL_API_KEY", ""),
			FromEmail:       getEnv("EMAIL_FROM_EMAIL", "noreply@localhost"),
			FromName:        getEnv("EMAIL_FROM_NAME", "Auth Service"),
			BaseURL:         getEnv("EMAIL_BASE_URL", "http://localhost:3000"),
			VerificationURL: getEnv("EMAIL_VERIFICATION_URL", "http://localhost:3000/verify-email"),
			ResetURL:        getEnv("EMAIL_RESET_URL", "http://localhost:3000/reset-password"),
			Enabled:         getBoolEnv("EMAIL_ENABLED", false),
		},
	}

	return cfg, nil
}

// DSN returns the PostgreSQL connection string
// Note: Password is included but not logged
func (c *DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.DBName, c.SSLMode,
	)
}

// SafeDSN returns DSN without password for logging
func (c *DatabaseConfig) SafeDSN() string {
	return fmt.Sprintf(
		"host=%s port=%s user=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.DBName, c.SSLMode,
	)
}

func (c *RedisConfig) Addr() string {
	return fmt.Sprintf("%s:%s", c.Host, c.Port)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getIntEnv(key string, defaultValue int) int {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	
	intVal, err := strconv.Atoi(value)
	if err != nil {
		// Use structured logging to prevent log injection
		log.Printf("[CONFIG] Invalid integer for key=%s, using default=%d", key, defaultValue)
		return defaultValue
	}
	return intVal
}

func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}

	duration, err := time.ParseDuration(value)
	if err != nil {
		// Use structured logging to prevent log injection
		log.Printf("[CONFIG] Invalid duration for key=%s, using default=%v", key, defaultValue)
		return defaultValue
	}
	return duration
}

func getBoolEnv(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}

	boolVal, err := strconv.ParseBool(value)
	if err != nil {
		// Use structured logging to prevent log injection
		log.Printf("[CONFIG] Invalid boolean for key=%s, using default=%v", key, defaultValue)
		return defaultValue
	}
	return boolVal
}
