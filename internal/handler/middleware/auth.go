package middleware

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/andressep95/auth-service/pkg/blacklist"
	"github.com/andressep95/auth-service/pkg/jwt"
)

// AuthMiddleware validates JWT tokens and extracts user claims
func AuthMiddleware(tokenService *jwt.TokenService, tokenBlacklist *blacklist.TokenBlacklist) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Extract Authorization header
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "missing authorization header",
			})
		}

		// Check if it's a Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid authorization header format",
			})
		}

		token := parts[1]
		if token == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "missing token",
			})
		}

		// Validate token first to get claims
		claims, err := tokenService.ValidateToken(token)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid token",
			})
		}

		// Check if token is blacklisted
		isBlacklisted, err := tokenBlacklist.IsBlacklisted(c.Context(), token)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to verify token status",
			})
		}

		if isBlacklisted {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "token has been revoked",
			})
		}

		// Check if user has been blacklisted (password change)
		if claims.IssuedAt != nil {
			userBlacklisted, err := tokenBlacklist.IsUserBlacklisted(c.Context(), claims.UserID.String(), claims.IssuedAt.Time)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": "failed to verify token status",
				})
			}
			if userBlacklisted {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "token invalidated due to password change",
				})
			}
		}

		// Check token type is "access"
		if claims.TokenType != "access" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid token type",
			})
		}

		// Store claims in fiber.Locals for downstream handlers
		c.Locals("user_id", claims.UserID)
		c.Locals("email", claims.Email)
		c.Locals("roles", claims.Roles)
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
