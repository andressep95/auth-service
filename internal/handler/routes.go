package handler

import (
	"github.com/gofiber/fiber/v2"
)

func SetupRoutes(
	app *fiber.App,
	authHandler *AuthHandler,
	userHandler *UserHandler,
	healthHandler *HealthHandler,
	authMiddleware fiber.Handler,
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
}
