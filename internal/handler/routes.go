package handler

import (
	"github.com/gofiber/fiber/v2"
)

func SetupRoutes(
	app *fiber.App,
	authHandler *AuthHandler,
	userHandler *UserHandler,
	roleHandler *RoleHandler,
	healthHandler *HealthHandler,
	authMiddleware fiber.Handler,
	requireAdmin fiber.Handler,
	requireModerator fiber.Handler,
) {
	// Health checks (public)
	app.Get("/health", healthHandler.Health)
	app.Get("/ready", healthHandler.Ready)

	// API v1
	api := app.Group("/api/v1")

	// Auth routes (public)
	auth := api.Group("/auth")
	auth.Post("/register", userHandler.Register)
	auth.Post("/login", authHandler.Login)
	auth.Post("/refresh", authHandler.RefreshToken)
	auth.Post("/logout", authHandler.Logout)

	// User routes (protected)
	users := api.Group("/users", authMiddleware)
	users.Get("/me", userHandler.GetMe)
	users.Get("/me/roles", roleHandler.GetMyRoles)
	users.Get("/me/permissions", roleHandler.GetMyPermissions)

	// Admin routes (require admin role)
	admin := api.Group("/admin", authMiddleware, requireAdmin)

	// Role management (admin only)
	roles := admin.Group("/roles")
	roles.Post("/", roleHandler.CreateRole)
	roles.Get("/", roleHandler.GetRoles)
	roles.Get("/:id", roleHandler.GetRole)
	roles.Put("/:id", roleHandler.UpdateRole)
	roles.Delete("/:id", roleHandler.DeleteRole)
	roles.Get("/:id/permissions", roleHandler.GetRolePermissions)

	// User role management (admin only)
	adminUsers := admin.Group("/users")
	adminUsers.Post("/:userId/roles/:roleId", roleHandler.AssignRoleToUser)
	adminUsers.Delete("/:userId/roles/:roleId", roleHandler.RemoveRoleFromUser)
	adminUsers.Get("/:userId/roles", roleHandler.GetUserRoles)

	// Moderator routes (require moderator or admin role)
	moderator := api.Group("/moderator", authMiddleware, requireModerator)
	moderator.Get("/users/:userId/roles", roleHandler.GetUserRoles)
}
