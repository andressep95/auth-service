package handler

import (
	"log"
	"net/http"

	"github.com/andressep95/auth-service/internal/service"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

type AuthPageHandler struct {
	appService    *service.AppService
	tenantService *service.TenantService
}

func NewAuthPageHandler(appService *service.AppService, tenantService *service.TenantService) *AuthPageHandler {
	return &AuthPageHandler{
		appService:    appService,
		tenantService: tenantService,
	}
}

// ShowLogin renders the login page
// GET /auth/login?app_id=xxx
func (h *AuthPageHandler) ShowLogin(c *fiber.Ctx) error {
	log.Printf("[AUTH_PAGE] ShowLogin called - Path: %s", c.Path())

	appIDStr := c.Query("app_id")
	if appIDStr == "" {
		return c.Status(http.StatusBadRequest).SendString("app_id is required")
	}

	appID, err := uuid.Parse(appIDStr)
	if err != nil {
		return c.Status(http.StatusBadRequest).SendString("Invalid app_id")
	}

	app, err := h.appService.GetAppByID(c.Context(), appID.String())
	if err != nil {
		return c.Status(http.StatusNotFound).SendString("App not found")
	}

	data := fiber.Map{
		"Title":        "Iniciar sesión",
		"AppName":      app.Name,
		"AppID":        app.ID.String(),
		"PrimaryColor": app.PrimaryColor,
		"Subtitle":     "Ingresa a tu cuenta",
	}

	if app.LogoURL != nil {
		data["Logo"] = *app.LogoURL
	}

	log.Printf("[AUTH_PAGE] Rendering login template with data: Title=%s, AppID=%s", data["Title"], data["AppID"])
	// Merge content block name into data
	data["Content"] = "login-content"
	return c.Render("login", data, "layout")
}

// ShowRegister renders the register page
// GET /auth/register?app_id=xxx
func (h *AuthPageHandler) ShowRegister(c *fiber.Ctx) error {
	log.Printf("[AUTH_PAGE] ShowRegister called - Path: %s", c.Path())

	appIDStr := c.Query("app_id")
	if appIDStr == "" {
		return c.Status(http.StatusBadRequest).SendString("app_id is required")
	}

	appID, err := uuid.Parse(appIDStr)
	if err != nil {
		return c.Status(http.StatusBadRequest).SendString("Invalid app_id")
	}

	app, err := h.appService.GetAppByID(c.Context(), appID.String())
	if err != nil {
		return c.Status(http.StatusNotFound).SendString("App not found")
	}

	data := fiber.Map{
		"Title":        "Crear cuenta",
		"AppName":      app.Name,
		"AppID":        app.ID.String(),
		"PrimaryColor": app.PrimaryColor,
		"Subtitle":     "Regístrate gratis",
	}

	if app.LogoURL != nil {
		data["Logo"] = *app.LogoURL
	}

	log.Printf("[AUTH_PAGE] Rendering register template with data: Title=%s, AppID=%s", data["Title"], data["AppID"])
	// Merge content block name into data
	data["Content"] = "register-content"
	return c.Render("register", data, "layout")
}

// ShowRegisterInvitation renders the invitation registration page
// GET /auth/register-invitation?token=xxx
func (h *AuthPageHandler) ShowRegisterInvitation(c *fiber.Ctx) error {
	token := c.Query("token")
	if token == "" {
		return c.Status(http.StatusBadRequest).SendString("Invitation token is required")
	}

	// Validate the invitation token
	invitation, tenant, err := h.tenantService.ValidateInvitationToken(c.Context(), token)
	if err != nil {
		errorData := fiber.Map{
			"Title":        "Invitación inválida",
			"AppName":      "Auth Service",
			"PrimaryColor": "#3B82F6",
			"Subtitle":     "Unirse al equipo",
			"Error":        err.Error(),
			"Token":        token,
			"Content":      "register-invitation-content",
		}
		return c.Render("register-invitation", errorData, "layout")
	}

	// Get app details
	app, err := h.appService.GetAppByID(c.Context(), tenant.AppID.String())
	if err != nil {
		return c.Status(http.StatusNotFound).SendString("App not found")
	}

	data := fiber.Map{
		"Title":        "Unirse a " + tenant.Name,
		"AppName":      app.Name,
		"AppID":        app.ID.String(),
		"PrimaryColor": app.PrimaryColor,
		"Subtitle":     "Completa tu registro",
		"Token":        token,
		"TenantName":   tenant.Name,
		"TenantID":     tenant.ID.String(),
	}

	if app.LogoURL != nil {
		data["Logo"] = *app.LogoURL
	}

	// Store invitation ID for later use
	data["InvitationID"] = invitation.ID.String()
	data["Content"] = "register-invitation-content"

	return c.Render("register-invitation", data, "layout")
}

// ShowVerifyEmail renders the email verification page
// GET /auth/verify-email?token=xxx
func (h *AuthPageHandler) ShowVerifyEmail(c *fiber.Ctx) error {
	log.Printf("[AUTH_PAGE] ShowVerifyEmail called - Path: %s", c.Path())

	token := c.Query("token")
	if token == "" {
		return c.Status(http.StatusBadRequest).SendString("Verification token is required")
	}

	appIDStr := c.Query("app_id", "7057e69d-818b-45db-b39b-9d1c84aca142") // Default app
	appID, err := uuid.Parse(appIDStr)
	if err != nil {
		appID, _ = uuid.Parse("7057e69d-818b-45db-b39b-9d1c84aca142")
	}

	app, err := h.appService.GetAppByID(c.Context(), appID.String())
	if err != nil {
		// Use default values if app not found
		log.Printf("[AUTH_PAGE] App not found, using defaults for verify-email")
		defaultData := fiber.Map{
			"Title":        "Verificar email",
			"AppName":      "Auth Service",
			"AppID":        appIDStr,
			"PrimaryColor": "#3B82F6",
			"Subtitle":     "Confirma tu dirección de correo",
			"Token":        token,
			"Content":      "verify-email-content",
		}
		return c.Render("verify-email", defaultData, "layout")
	}

	data := fiber.Map{
		"Title":        "Verificar email",
		"AppName":      app.Name,
		"AppID":        app.ID.String(),
		"PrimaryColor": app.PrimaryColor,
		"Subtitle":     "Confirma tu dirección de correo",
		"Token":        token,
	}

	if app.LogoURL != nil {
		data["Logo"] = *app.LogoURL
	}

	log.Printf("[AUTH_PAGE] Rendering verify-email template with data: Title=%s, AppID=%s", data["Title"], data["AppID"])
	data["Content"] = "verify-email-content"
	return c.Render("verify-email", data, "layout")
}

// ShowResetPassword renders the reset password page
// GET /auth/reset-password?token=xxx
func (h *AuthPageHandler) ShowResetPassword(c *fiber.Ctx) error {
	log.Printf("[AUTH_PAGE] ShowResetPassword called - Path: %s", c.Path())

	token := c.Query("token")
	if token == "" {
		return c.Status(http.StatusBadRequest).SendString("Reset token is required")
	}

	appIDStr := c.Query("app_id", "7057e69d-818b-45db-b39b-9d1c84aca142") // Default app
	appID, err := uuid.Parse(appIDStr)
	if err != nil {
		appID, _ = uuid.Parse("7057e69d-818b-45db-b39b-9d1c84aca142")
	}

	app, err := h.appService.GetAppByID(c.Context(), appID.String())
	if err != nil {
		// Use default values if app not found
		log.Printf("[AUTH_PAGE] App not found, using defaults for reset-password")
		defaultData := fiber.Map{
			"Title":        "Restablecer contraseña",
			"AppName":      "Auth Service",
			"AppID":        appIDStr,
			"PrimaryColor": "#3B82F6",
			"Subtitle":     "Crea una nueva contraseña",
			"Token":        token,
			"Content":      "reset-password-content",
		}
		return c.Render("reset-password", defaultData, "layout")
	}

	data := fiber.Map{
		"Title":        "Restablecer contraseña",
		"AppName":      app.Name,
		"AppID":        app.ID.String(),
		"PrimaryColor": app.PrimaryColor,
		"Subtitle":     "Crea una nueva contraseña",
		"Token":        token,
	}

	if app.LogoURL != nil {
		data["Logo"] = *app.LogoURL
	}

	log.Printf("[AUTH_PAGE] Rendering reset-password template with data: Title=%s, AppID=%s", data["Title"], data["AppID"])
	data["Content"] = "reset-password-content"
	return c.Render("reset-password", data, "layout")
}
