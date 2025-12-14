package middleware

import (
	"log"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/andressep95/auth-service/pkg/blacklist"
	"github.com/andressep95/auth-service/pkg/jwt"
)

// AuthMiddleware validates JWT tokens and extracts user claims
func AuthMiddleware(tokenService *jwt.TokenService, tokenBlacklist *blacklist.TokenBlacklist) fiber.Handler {
	return func(c *fiber.Ctx) error {
		path := c.Path()
		log.Printf("[AUTH_MIDDLEWARE] Request to: %s", path)

		// Extract Authorization header
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			log.Printf("[AUTH_MIDDLEWARE] Missing authorization header")
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "missing authorization header",
			})
		}

		// Check if it's a Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			log.Printf("[AUTH_MIDDLEWARE] Invalid auth header format")
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid authorization header format",
			})
		}

		token := parts[1]
		if token == "" {
			log.Printf("[AUTH_MIDDLEWARE] Empty token")
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "missing token",
			})
		}

		log.Printf("[AUTH_MIDDLEWARE] Token found, validating...")

		// Validate token first to get claims
		claims, err := tokenService.ValidateToken(token)
		if err != nil {
			log.Printf("[AUTH_MIDDLEWARE] Token validation failed: %v", err)
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid token",
			})
		}

		log.Printf("[AUTH_MIDDLEWARE] Token valid - User: %s, Type: %s", claims.Email, claims.TokenType)

		// Check if token is blacklisted
		isBlacklisted, err := tokenBlacklist.IsBlacklisted(c.Context(), token)
		if err != nil {
			log.Printf("[AUTH_MIDDLEWARE] Blacklist check failed: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to verify token status",
			})
		}

		if isBlacklisted {
			log.Printf("[AUTH_MIDDLEWARE] Token is blacklisted")
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "token has been revoked",
			})
		}

		// Check if user has been blacklisted (password change)
		if claims.IssuedAt != nil {
			userBlacklisted, err := tokenBlacklist.IsUserBlacklisted(c.Context(), claims.UserID.String(), claims.IssuedAt.Time)
			if err != nil {
				log.Printf("[AUTH_MIDDLEWARE] User blacklist check failed: %v", err)
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": "failed to verify token status",
				})
			}
			if userBlacklisted {
				log.Printf("[AUTH_MIDDLEWARE] User is blacklisted (password changed)")
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "token invalidated due to password change",
				})
			}
		}

		// Check token type is "access"
		if claims.TokenType != "access" {
			log.Printf("[AUTH_MIDDLEWARE] Invalid token type: %s", claims.TokenType)
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid token type",
			})
		}

		log.Printf("[AUTH_MIDDLEWARE] All checks passed for user: %s (app_id: %s, tenant_id: %s)", claims.Email, claims.AppID, claims.TenantID)

		// Store claims in fiber.Locals for downstream handlers
		c.Locals("user_id", claims.UserID)
		c.Locals("email", claims.Email)
		c.Locals("roles", claims.Roles)
		c.Locals("app_id", claims.AppID)       // Store app_id from token
		c.Locals("tenant_id", claims.TenantID) // Store tenant_id from token
		c.Locals("claims", claims)
		c.Locals("token", token) // Store token for potential invalidation

		// Store session ID if present (for session management)
		if claims.SessionID != nil {
			c.Locals("session_id", *claims.SessionID)
		}

		// Continue to next handler
		return c.Next()
	}
}

// RequireSuperAdmin checks if user has super_admin role
func RequireSuperAdmin() fiber.Handler {
	return func(c *fiber.Ctx) error {
		roles, ok := c.Locals("roles").([]string)
		if !ok {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":          "Forbidden: no roles found",
				"required_roles": []string{"super_admin"},
			})
		}

		// Check if user has super_admin role
		for _, role := range roles {
			if role == "super_admin" {
				return c.Next()
			}
		}

		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error":          "Forbidden: insufficient permissions",
			"required_roles": []string{"super_admin"},
		})
	}
}
