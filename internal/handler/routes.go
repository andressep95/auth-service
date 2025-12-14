package handler

import (
	"github.com/gofiber/fiber/v2"
)

func SetupRoutes(
	app *fiber.App,
	authHandler *AuthHandler,
	userHandler *UserHandler,
	roleHandler *RoleHandler,
	passwordHandler *PasswordHandler,
	sessionHandler *SessionHandler,
	healthHandler *HealthHandler,
	jwksHandler *JWKSHandler,
	setupHandler *SetupHandler,
	appHandler *AppHandler,
	tenantHandler *TenantHandler,
	authPageHandler *AuthPageHandler,
	authMiddleware fiber.Handler,
	requireAdmin fiber.Handler,
	requireModerator fiber.Handler,
	requireSuperAdmin fiber.Handler,
) {
	// Health checks (public)
	app.Get("/health", healthHandler.Health)
	app.Get("/ready", healthHandler.Ready)

	// JWKS endpoint (public)
	app.Get("/.well-known/jwks.json", jwksHandler.GetJWKS)

	// Setup endpoint (public, one-time use)
	app.Post("/api/v1/setup/super-admin", setupHandler.CreateSuperAdmin)

	// HTML auth pages (public)
	authPages := app.Group("/auth")
	authPages.Get("/login", authPageHandler.ShowLogin)
	authPages.Get("/register", authPageHandler.ShowRegister)
	authPages.Get("/register-invitation", authPageHandler.ShowRegisterInvitation)
	authPages.Get("/verify-email", authPageHandler.ShowVerifyEmail)
	authPages.Get("/forgot-password", authPageHandler.ShowForgotPassword)
	authPages.Get("/reset-password", authPageHandler.ShowResetPassword)

	// API v1
	api := app.Group("/api/v1")

	// Auth routes (public)
	auth := api.Group("/auth")
	auth.Post("/register", userHandler.Register)
	auth.Post("/login", authHandler.Login)
	auth.Post("/refresh", authHandler.RefreshToken)
	auth.Post("/logout", authHandler.Logout)
	auth.Post("/verify-email", userHandler.VerifyEmail)
	auth.Post("/resend-verification", userHandler.ResendVerificationEmail)
	auth.Post("/forgot-password", userHandler.ForgotPassword)
	auth.Post("/reset-password", userHandler.ResetPassword)
	auth.Post("/register-with-invitation", authHandler.RegisterWithInvitation)

	// User routes (protected)
	users := api.Group("/users", authMiddleware)
	users.Get("/me", userHandler.GetMe)
	users.Put("/me/password", passwordHandler.ChangePassword)
	users.Get("/me/roles", roleHandler.GetMyRoles)
	users.Get("/me/permissions", roleHandler.GetMyPermissions)

	// Session management (protected)
	users.Get("/me/sessions", sessionHandler.GetMySessions)
	users.Delete("/me/sessions/:id", sessionHandler.DeleteSession)
	users.Delete("/me/sessions", sessionHandler.DeleteAllSessions)

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

	// User management (admin only)
	adminUsers := admin.Group("/users")
	adminUsers.Get("/", userHandler.ListUsers)
	adminUsers.Get("/:id", userHandler.GetUser)
	adminUsers.Post("/:userId/roles/:roleId", roleHandler.AssignRoleToUser)
	adminUsers.Delete("/:userId/roles/:roleId", roleHandler.RemoveRoleFromUser)
	adminUsers.Get("/:userId/roles", roleHandler.GetUserRoles)

	// Moderator routes (require moderator or admin role)
	moderator := api.Group("/moderator", authMiddleware, requireModerator)
	moderator.Get("/users/:userId/roles", roleHandler.GetUserRoles)

	// Super admin routes (require super_admin role)
	superAdmin := api.Group("/super-admin", authMiddleware, requireSuperAdmin)
	superAdmin.Post("/apps", appHandler.CreateApp)
	superAdmin.Get("/apps", appHandler.ListApps)
	superAdmin.Get("/apps/:id", appHandler.GetApp)

	// Tenant management routes (admin only)
	tenants := admin.Group("/tenants")
	tenants.Post("/", tenantHandler.CreateTenant)
	tenants.Get("/", tenantHandler.ListTenants)
	tenants.Get("/:id", tenantHandler.GetTenant)
	tenants.Put("/:id", tenantHandler.UpdateTenant)

	// Invitation management routes (admin only)
	tenants.Post("/:id/invitations", tenantHandler.CreateInvitation)
	tenants.Get("/:id/invitations", tenantHandler.ListInvitations)
	tenants.Delete("/:id/invitations/:invitationId", tenantHandler.RevokeInvitation)

	// Public invitation validation (no auth required)
	auth.Get("/validate-invitation/:token", tenantHandler.ValidateInvitation)
}
