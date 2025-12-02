package middleware

import (
	"strings"

	"github.com/andressep95/auth-service/internal/config"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

// CORSMiddleware configures and returns CORS middleware
func CORSMiddleware(cfg *config.Config) fiber.Handler {
	// Limpiar espacios en blanco de los orígenes
	origins := strings.ReplaceAll(cfg.CORS.AllowedOrigins, " ", "")
	
	return cors.New(cors.Config{
		AllowOrigins:     origins,
		AllowMethods:     "GET,POST,PUT,DELETE,OPTIONS",
		AllowHeaders:     "Content-Type,Authorization,X-Requested-With",
		AllowCredentials: true,
	})
}
