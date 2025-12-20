package handler

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/andressep95/auth-service/internal/domain"
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

// ShowLogin renders the login page with OAuth2 support
// GET /auth/login (ONLY auto-detects from Origin header - SECURE)
// ⚠️ NO query params accepted for security reasons - prevents app_id leakage
func (h *AuthPageHandler) ShowLogin(c *fiber.Ctx) error {
	log.Printf("[AUTH_PAGE] ShowLogin called - Path: %s", c.Path())

	var app *domain.App
	var suggestedRedirectURI string

	// SECURITY: Only auto-detect from Origin header (controlled by browser)
	// Check if CORS middleware already detected the app
	if autoApp := c.Locals("auto_detected_app"); autoApp != nil {
		app = autoApp.(*domain.App)
		log.Printf("[AUTH_PAGE] App pre-detected by CORS middleware: %s", app.Name)

		// Get suggested redirect from CORS if available
		resolution, err := h.appService.ResolveAppFromOrigin(c.Context(), c.Get("Origin"))
		if err == nil {
			suggestedRedirectURI = resolution.SuggestedRedirectURI
		}
	} else {
		// CORS didn't detect it, try manually
		origin := c.Get("Origin")
		if origin == "" {
			origin = c.Get("Referer") // Fallback to Referer for direct browser navigation
			// Parse Referer to get origin
			if origin != "" {
				if parsedURL, err := url.Parse(origin); err == nil {
					origin = parsedURL.Scheme + "://" + parsedURL.Host
				}
			}
		}

		// If still empty (direct navigation), construct from Host header
		if origin == "" {
			host := c.Get("Host")
			if host != "" {
				// Determine scheme from protocol
				scheme := "http"
				if c.Protocol() == "https" || c.Get("X-Forwarded-Proto") == "https" {
					scheme = "https"
				}
				origin = scheme + "://" + host
				log.Printf("[AUTH_PAGE] Constructed origin from Host header: %s", origin)
			}
		}

		if origin == "" {
			return c.Status(http.StatusBadRequest).SendString("Access denied: Could not determine origin. Please access from registered web application.")
		}

		log.Printf("[AUTH_PAGE] Auto-detecting from origin: %s", origin)

		resolution, err := h.appService.ResolveAppFromOrigin(c.Context(), origin)
		if err != nil {
			log.Printf("[AUTH_PAGE] Failed to resolve app from origin %s: %v", origin, err)
			return c.Status(http.StatusForbidden).SendString(fmt.Sprintf("Access denied: Origin '%s' not registered. Contact admin to whitelist your domain.", origin))
		}

		app = resolution.App
		suggestedRedirectURI = resolution.SuggestedRedirectURI

		log.Printf("[AUTH_PAGE] App auto-detected: %s (suggested redirect: %s)", app.Name, suggestedRedirectURI)
	}

	// OAuth2 parameters - all auto-generated for security
	redirectURI := suggestedRedirectURI
	state := c.Query("state", "") // State can come from frontend (CSRF protection)
	responseType := "code"          // Always OAuth2 Authorization Code Flow
	scope := c.Query("scope", "")   // Optional scope from frontend

	data := fiber.Map{
		"Title":        "Iniciar sesión",
		"AppName":      app.Name,
		"AppID":        app.ID.String(),
		"PrimaryColor": app.PrimaryColor,
		"Subtitle":     "Ingresa a tu cuenta",
		// OAuth2 parameters passed to the form
		"RedirectURI":  redirectURI,
		"State":        state,
		"ResponseType": responseType,
		"Scope":        scope,
	}

	if app.LogoURL != nil {
		data["Logo"] = *app.LogoURL
	}

	log.Printf("[AUTH_PAGE] Rendering login template - App: %s, OAuth2: %v, RedirectURI: %s",
		app.Name, redirectURI != "", redirectURI)

	data["Content"] = "login-content"
	return c.Render("login", data, "layout")
}

// ShowRegister renders the register page with SECURE auto-detection
// GET /auth/register (ONLY auto-detects from Origin header - SECURE)
// ⚠️ NO query params accepted for security reasons - prevents app_id leakage
func (h *AuthPageHandler) ShowRegister(c *fiber.Ctx) error {
	log.Printf("[AUTH_PAGE] ShowRegister called - Path: %s", c.Path())

	var app *domain.App

	// SECURITY: Only auto-detect from Origin header (controlled by browser)
	// Check if CORS middleware already detected the app
	if autoApp := c.Locals("auto_detected_app"); autoApp != nil {
		app = autoApp.(*domain.App)
		log.Printf("[AUTH_PAGE] App pre-detected by CORS middleware: %s", app.Name)
	} else {
		// CORS didn't detect it, try manually
		origin := c.Get("Origin")
		if origin == "" {
			origin = c.Get("Referer") // Fallback to Referer for direct browser navigation
			// Parse Referer to get origin
			if origin != "" {
				if parsedURL, err := url.Parse(origin); err == nil {
					origin = parsedURL.Scheme + "://" + parsedURL.Host
				}
			}
		}

		// If still empty (direct navigation), construct from Host header
		if origin == "" {
			host := c.Get("Host")
			if host != "" {
				// Determine scheme from protocol
				scheme := "http"
				if c.Protocol() == "https" || c.Get("X-Forwarded-Proto") == "https" {
					scheme = "https"
				}
				origin = scheme + "://" + host
				log.Printf("[AUTH_PAGE] Constructed origin from Host header: %s", origin)
			}
		}

		if origin == "" {
			return c.Status(http.StatusBadRequest).SendString("Access denied: Could not determine origin. Please access from registered web application.")
		}

		log.Printf("[AUTH_PAGE] Auto-detecting from origin: %s", origin)

		resolution, err := h.appService.ResolveAppFromOrigin(c.Context(), origin)
		if err != nil {
			log.Printf("[AUTH_PAGE] Failed to resolve app from origin %s: %v", origin, err)
			return c.Status(http.StatusForbidden).SendString(fmt.Sprintf("Access denied: Origin '%s' not registered. Contact admin to whitelist your domain.", origin))
		}

		app = resolution.App
		log.Printf("[AUTH_PAGE] App auto-detected: %s", app.Name)
	}

	csrfToken := c.Cookies("csrf_token")

	if csrfToken == "" {
		csrfToken = uuid.New().String()

		isProd := os.Getenv("ENVIRONMENT") == "production"

		c.Cookie(&fiber.Cookie{
			Name:     "csrf_token",
			Value:    csrfToken,
			HTTPOnly: true,
			Secure:   isProd,
			SameSite: fiber.CookieSameSiteLaxMode,
			Path:     "/",
			Expires:  time.Now().Add(10 * time.Minute),
		})
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

	// Merge content block name into data
	data["CSRFToken"] = csrfToken
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

// ShowVerifyEmail renders the email verification page with SECURE auto-detection
// GET /auth/verify-email?token=xxx
func (h *AuthPageHandler) ShowVerifyEmail(c *fiber.Ctx) error {
	log.Printf("[AUTH_PAGE] ShowVerifyEmail called - Path: %s", c.Path())

	token := c.Query("token")
	if token == "" {
		return c.Status(http.StatusBadRequest).SendString("Verification token is required")
	}

	var app *domain.App

	// Try auto-detection from Origin/Referer/Host
	if autoApp := c.Locals("auto_detected_app"); autoApp != nil {
		app = autoApp.(*domain.App)
		log.Printf("[AUTH_PAGE] App pre-detected: %s", app.Name)
	} else {
		origin := getOriginFromRequest(c)
		if origin != "" {
			log.Printf("[AUTH_PAGE] Auto-detecting from origin: %s", origin)
			resolution, err := h.appService.ResolveAppFromOrigin(c.Context(), origin)
			if err == nil {
				app = resolution.App
				log.Printf("[AUTH_PAGE] App auto-detected: %s", app.Name)
			}
		}
	}

	// Fallback to default app if auto-detection failed
	if app == nil {
		log.Printf("[AUTH_PAGE] Using default app for verify-email")
		defaultAppID, _ := uuid.Parse("7057e69d-818b-45db-b39b-9d1c84aca142")
		var err error
		app, err = h.appService.GetAppByID(c.Context(), defaultAppID.String())
		if err != nil {
			// Use hardcoded defaults if even default app not found
			defaultData := fiber.Map{
				"Title":        "Verificar email",
				"AppName":      "Auth Service",
				"AppID":        "7057e69d-818b-45db-b39b-9d1c84aca142",
				"PrimaryColor": "#3B82F6",
				"Subtitle":     "Confirma tu dirección de correo",
				"Token":        token,
				"Content":      "verify-email-content",
			}
			return c.Render("verify-email", defaultData, "layout")
		}
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

// ShowForgotPassword renders the forgot password page
// GET /auth/forgot-password?app_id=xxx
func (h *AuthPageHandler) ShowForgotPassword(c *fiber.Ctx) error {
	log.Printf("[AUTH_PAGE] ShowForgotPassword called - Path: %s", c.Path())

	var app *domain.App

	// Try auto-detection from Origin/Referer/Host
	if autoApp := c.Locals("auto_detected_app"); autoApp != nil {
		app = autoApp.(*domain.App)
		log.Printf("[AUTH_PAGE] App pre-detected: %s", app.Name)
	} else {
		origin := getOriginFromRequest(c)
		if origin != "" {
			log.Printf("[AUTH_PAGE] Auto-detecting from origin: %s", origin)
			resolution, err := h.appService.ResolveAppFromOrigin(c.Context(), origin)
			if err == nil {
				app = resolution.App
				log.Printf("[AUTH_PAGE] App auto-detected: %s", app.Name)
			}
		}
	}

	// Fallback to default app if auto-detection failed
	if app == nil {
		log.Printf("[AUTH_PAGE] Using default app for forgot-password")
		defaultAppID, _ := uuid.Parse("7057e69d-818b-45db-b39b-9d1c84aca142")
		var err error
		app, err = h.appService.GetAppByID(c.Context(), defaultAppID.String())
		if err != nil {
			// Use hardcoded defaults if even default app not found
			defaultData := fiber.Map{
				"Title":        "Recuperar contraseña",
				"AppName":      "Auth Service",
				"AppID":        "7057e69d-818b-45db-b39b-9d1c84aca142",
				"PrimaryColor": "#3B82F6",
				"Subtitle":     "Solicita un enlace de recuperación",
				"Content":      "forgot-password-content",
			}
			return c.Render("forgot-password", defaultData, "layout")
		}
	}

	data := fiber.Map{
		"Title":        "Recuperar contraseña",
		"AppName":      app.Name,
		"AppID":        app.ID.String(),
		"PrimaryColor": app.PrimaryColor,
		"Subtitle":     "Solicita un enlace de recuperación",
	}

	if app.LogoURL != nil {
		data["Logo"] = *app.LogoURL
	}

	log.Printf("[AUTH_PAGE] Rendering forgot-password template with data: Title=%s, AppID=%s", data["Title"], data["AppID"])
	data["Content"] = "forgot-password-content"
	return c.Render("forgot-password", data, "layout")
}

// ShowResetPassword renders the reset password page
// GET /auth/reset-password?token=xxx
func (h *AuthPageHandler) ShowResetPassword(c *fiber.Ctx) error {
	log.Printf("[AUTH_PAGE] ShowResetPassword called - Path: %s", c.Path())

	token := c.Query("token")
	if token == "" {
		return c.Status(http.StatusBadRequest).SendString("Reset token is required")
	}

	var app *domain.App

	// Try auto-detection from Origin/Referer/Host
	if autoApp := c.Locals("auto_detected_app"); autoApp != nil {
		app = autoApp.(*domain.App)
		log.Printf("[AUTH_PAGE] App pre-detected: %s", app.Name)
	} else {
		origin := getOriginFromRequest(c)
		if origin != "" {
			log.Printf("[AUTH_PAGE] Auto-detecting from origin: %s", origin)
			resolution, err := h.appService.ResolveAppFromOrigin(c.Context(), origin)
			if err == nil {
				app = resolution.App
				log.Printf("[AUTH_PAGE] App auto-detected: %s", app.Name)
			}
		}
	}

	// Fallback to default app if auto-detection failed
	if app == nil {
		log.Printf("[AUTH_PAGE] Using default app for reset-password")
		defaultAppID, _ := uuid.Parse("7057e69d-818b-45db-b39b-9d1c84aca142")
		var err error
		app, err = h.appService.GetAppByID(c.Context(), defaultAppID.String())
		if err != nil {
			// Use hardcoded defaults if even default app not found
			defaultData := fiber.Map{
				"Title":        "Restablecer contraseña",
				"AppName":      "Auth Service",
				"AppID":        "7057e69d-818b-45db-b39b-9d1c84aca142",
				"PrimaryColor": "#3B82F6",
				"Subtitle":     "Crea una nueva contraseña",
				"Token":        token,
				"Content":      "reset-password-content",
			}
			return c.Render("reset-password", defaultData, "layout")
		}
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
