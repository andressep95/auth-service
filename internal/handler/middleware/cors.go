package middleware

import (
	"log"
	"strings"

	"github.com/andressep95/auth-service/internal/config"
	"github.com/andressep95/auth-service/internal/service"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/google/uuid"
)

// CORSMiddleware configures and returns CORS middleware (static configuration)
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

// DynamicCORS creates a dynamic CORS middleware that validates origins against app's web_origins
func DynamicCORS(appService *service.AppService) fiber.Handler {
	return func(c *fiber.Ctx) error {
		origin := c.Get("Origin")

		// If no Origin header, allow the request (same-origin or non-browser)
		if origin == "" {
			return c.Next()
		}

		log.Printf("[CORS] Request from origin: %s", origin)

		// Try to get app_id from different sources
		appID := extractAppID(c)

		// Strategy 1: If no app_id, try to resolve from origin (auto-detection)
		if appID == "" {
			log.Printf("[CORS] No app_id found, attempting auto-detection from origin")

			// Try to find app by origin
			resolution, err := appService.ResolveAppFromOrigin(c.Context(), origin)
			if err == nil && resolution.App != nil {
				// App found! Use it for CORS validation
				appID = resolution.App.ID.String()
				log.Printf("[CORS] App auto-detected: %s (ID: %s)", resolution.App.Name, appID)

				// Set app_id in context for downstream handlers
				c.Locals("auto_detected_app_id", appID)
				c.Locals("auto_detected_app", resolution.App)
			} else {
				// No app found for origin - use permissive CORS (backward compatible)
				log.Printf("[CORS] No app found for origin, using permissive CORS")
				c.Set("Access-Control-Allow-Origin", origin)
				c.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
				c.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
				c.Set("Access-Control-Allow-Credentials", "true")
				c.Set("Access-Control-Max-Age", "3600")

				if c.Method() == "OPTIONS" {
					return c.SendStatus(fiber.StatusNoContent)
				}

				return c.Next()
			}
		}

		// Validate app_id format
		appUUID, err := uuid.Parse(appID)
		if err != nil {
			log.Printf("[CORS] Invalid app_id format: %s", appID)
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid app_id format",
			})
		}

		// Get app configuration
		app, err := appService.GetAppByID(c.Context(), appUUID.String())
		if err != nil {
			log.Printf("[CORS] App not found: %s", appID)
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "App not found",
			})
		}

		// Check if origin is in the app's whitelist
		originAllowed := false

		// If no web_origins configured, allow all origins (development mode)
		if len(app.WebOrigins) == 0 {
			log.Printf("[CORS] No web_origins configured for app %s, allowing all origins", appID)
			originAllowed = true
		} else {
			// Check if origin matches any whitelisted origin
			for _, allowedOrigin := range app.WebOrigins {
				if matchOrigin(origin, allowedOrigin) {
					originAllowed = true
					log.Printf("[CORS] Origin %s matched whitelist entry: %s", origin, allowedOrigin)
					break
				}
			}
		}

		if !originAllowed {
			log.Printf("[CORS] Origin %s not allowed for app %s", origin, appID)
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Origin not allowed",
			})
		}

		// Set CORS headers
		c.Set("Access-Control-Allow-Origin", origin)
		c.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
		c.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		c.Set("Access-Control-Allow-Credentials", "true")
		c.Set("Access-Control-Max-Age", "3600")

		// Handle preflight request
		if c.Method() == "OPTIONS" {
			return c.SendStatus(fiber.StatusNoContent)
		}

		return c.Next()
	}
}

// extractAppID tries to extract app_id from various sources in the request
func extractAppID(c *fiber.Ctx) string {
	// 1. Check query parameter
	appID := c.Query("app_id")
	if appID != "" {
		return appID
	}

	// 2. Check form data (for POST requests)
	appID = c.FormValue("app_id")
	if appID != "" {
		return appID
	}

	// 3. Check JSON body
	type AppIDBody struct {
		AppID string `json:"app_id"`
	}
	var body AppIDBody
	if err := c.BodyParser(&body); err == nil && body.AppID != "" {
		return body.AppID
	}

	// 4. Check custom header
	appID = c.Get("X-App-ID")
	if appID != "" {
		return appID
	}

	return ""
}

// matchOrigin checks if an origin matches the allowed origin pattern
// Supports exact match and wildcard subdomain matching (e.g., *.example.com)
func matchOrigin(origin, allowed string) bool {
	// Exact match
	if origin == allowed {
		return true
	}

	// Wildcard subdomain matching
	if strings.HasPrefix(allowed, "*.") {
		domain := strings.TrimPrefix(allowed, "*.")
		return strings.HasSuffix(origin, domain)
	}

	return false
}
