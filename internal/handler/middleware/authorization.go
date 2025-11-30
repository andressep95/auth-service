package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/andressep95/auth-service/internal/service"
)

// RequireRole middleware verifies that the user has at least one of the required roles
func RequireRole(roleService *service.RoleService, roles ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get user ID from context (set by AuthMiddleware)
		userID, ok := c.Locals("user_id").(uuid.UUID)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Unauthorized",
			})
		}

		// Check if user has any of the required roles
		for _, role := range roles {
			hasRole, err := roleService.HasRole(c.Context(), userID, role)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": "Failed to check role",
				})
			}

			if hasRole {
				// User has required role, allow access
				c.Locals("current_role", role)
				return c.Next()
			}
		}

		// User doesn't have any required role
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "Forbidden: insufficient permissions",
			"required_roles": roles,
		})
	}
}

// RequirePermission middleware verifies that the user has a specific permission
func RequirePermission(roleService *service.RoleService, resource, action string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get user ID from context (set by AuthMiddleware)
		userID, ok := c.Locals("user_id").(uuid.UUID)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Unauthorized",
			})
		}

		// Check if user has the required permission
		hasPermission, err := roleService.HasPermission(c.Context(), userID, resource, action)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to check permission",
			})
		}

		if !hasPermission {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Forbidden: missing required permission",
				"required_permission": fiber.Map{
					"resource": resource,
					"action":   action,
				},
			})
		}

		return c.Next()
	}
}

// RequireAnyPermission middleware verifies that the user has at least one of the required permissions
func RequireAnyPermission(roleService *service.RoleService, permissions []struct{ Resource, Action string }) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID, ok := c.Locals("user_id").(uuid.UUID)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Unauthorized",
			})
		}

		// Check if user has any of the required permissions
		for _, perm := range permissions {
			hasPermission, err := roleService.HasPermission(c.Context(), userID, perm.Resource, perm.Action)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": "Failed to check permission",
				})
			}

			if hasPermission {
				return c.Next()
			}
		}

		// User doesn't have any required permission
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "Forbidden: insufficient permissions",
		})
	}
}

// RequireAdmin is a convenience middleware for requiring admin role
func RequireAdmin(roleService *service.RoleService) fiber.Handler {
	return RequireRole(roleService, "admin")
}

// RequireModerator is a convenience middleware for requiring moderator or admin role
func RequireModerator(roleService *service.RoleService) fiber.Handler {
	return RequireRole(roleService, "admin", "moderator")
}
